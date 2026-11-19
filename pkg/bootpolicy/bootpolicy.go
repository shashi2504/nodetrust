// Package bootpolicy checks a node's boot event log, event by event, after
// it has been replayed to the PCRs of a verified quote (blueprint Phase 4,
// step 4.1). Fixed PCR values do not work for this boot chain: PCR 1 names
// the instance's own EBS volume, and GRUB writes grubenv on every boot and
// measures it into PCR 9. So each event is checked on its own:
//
//	PCR 0     firmware: the replayed value is in an allow-list
//	PCR 1     only boot-option variables; one must name this instance's root volume
//	PCR 2,3,6 only the separator
//	PCR 4     exactly three EFI applications, in order: shim, GRUB, then the
//	          kernel the command line names, each by its Authenticode hash in the
//	          signed manifest at a path the policy allows for that stage
//	PCR 5     the GPT of the AMI's disk, and the exit-boot-services actions
//	PCR 7     Secure Boot on, and PK, KEK, db, dbx and the authorities as expected
//	PCR 8     every GRUB command is logged as text that matches its digest, and the
//	          kernel command line is exactly the expected one
//	PCR 9     every file GRUB loaded matches the signed manifest (except grubenv),
//	          the initrd the kernel received is one of them, and the load
//	          options the kernel received are the expected command line
//
// Events whose digest is the hash of their own data are also checked for
// that, so the text and variable contents the checks read are proven, not
// just present.
package bootpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode/utf16"

	"nodetrust/pkg/eventlog"
	"nodetrust/pkg/manifest"
)

// Value is an allowed digest with the reason it is allowed.
type Value struct {
	SHA256 string `json:"sha256"`
	Why    string `json:"why"`
}

// EFIChain lists the manifest paths each PCR 4 stage may load from. The
// third stage, the kernel, is the image the AMI's command line names.
type EFIChain struct {
	Shim []string `json:"shim"`
	Grub []string `json:"grub"`
}

// AMI holds the references specific to one golden AMI.
type AMI struct {
	GPT           string `json:"gpt_event_sha256"` // EV_EFI_GPT_EVENT digest (the disk image's partition table)
	KernelCmdline string `json:"kernel_cmdline"`
}

// Policy is the boot policy (infra/phase4/boot-policy.json).
type Policy struct {
	FirmwarePCR0    []Value           `json:"firmware_pcr0"`
	SecureBoot      map[string]string `json:"secure_boot"` // "SecureBoot", "PK", ..., "authority:db" -> event digest
	BootAction      string            `json:"pcr4_action"`
	EFIChain        EFIChain          `json:"efi_boot_chain"`
	RequiredCmdline []string          `json:"required_cmdline"`
	GrubPartitions  map[string]string `json:"grub_partitions"` // "(hd0,gpt16)" -> "/boot"
	GrubRoot        string            `json:"grub_root"`       // where paths without a device live
	MutableFiles    []string          `json:"mutable_files"`
	AMIs            map[string]AMI    `json:"amis"`
}

// LoadPolicy parses and checks a policy.
func LoadPolicy(b []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("boot policy: %w", err)
	}
	if len(p.FirmwarePCR0) == 0 || len(p.SecureBoot) == 0 || p.GrubRoot == "" || len(p.AMIs) == 0 ||
		len(p.EFIChain.Shim) == 0 || len(p.EFIChain.Grub) == 0 {
		return nil, fmt.Errorf("boot policy: firmware_pcr0, secure_boot, efi_boot_chain, grub_root and amis are required")
	}
	return &p, nil
}

// Finding is the result of one check.
type Finding struct {
	PCR    int
	Check  string
	OK     bool
	Detail string
}

// Result of a boot check.
type Result struct {
	Findings []Finding
	Initrd   string // what the kernel got as initrd: a path from the manifest
}

// Pass reports whether every check passed.
func (r *Result) Pass() bool {
	for _, f := range r.Findings {
		if !f.OK {
			return false
		}
	}
	return len(r.Findings) > 0
}

func (r *Result) add(pcr int, check string, ok bool, format string, a ...any) {
	r.Findings = append(r.Findings, Finding{PCR: pcr, Check: check, OK: ok, Detail: fmt.Sprintf(format, a...)})
}

// Input is everything a boot check needs. Quoted must come from a verified
// quote; Manifest from a manifest verified against its signed statement.
type Input struct {
	Log          *eventlog.Log
	Quoted       map[int][]byte
	Manifest     map[string]manifest.Entry
	AMI          string
	RootVolumeID string // e.g. "vol-0af96f3cd779bc1e4", from the cloud API; empty to skip
}

func hexs(b []byte) string { return hex.EncodeToString(b) }

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// selfDigest returns what the digest of an event must be when it is the hash
// of the event's own data, or nil when it is not (files, PE images, firmware).
func selfDigest(e *eventlog.Event) []byte {
	switch e.Type {
	case eventlog.EvSeparator, eventlog.EvEFIAction, eventlog.EvEFIGPTEvent, eventlog.EvSCRTMVersion,
		eventlog.EvEFIVariableDriverConfig, eventlog.EvEFIVariableAuthority:
		return sum(e.Data)
	case eventlog.EvEFIVariableBoot:
		if v, err := e.ParseVariable(); err == nil {
			return sum(v.Data)
		}
	case eventlog.EvIPL:
		if e.PCR == 8 {
			s := strings.TrimRight(string(e.Data), "\x00")
			for _, p := range []string{"grub_cmd: ", "kernel_cmdline: "} {
				if strings.HasPrefix(s, p) {
					return sum([]byte(s[len(p):]))
				}
			}
			return sum([]byte(s))
		}
	}
	return nil
}

// Evaluate runs every check. It never stops early, so a report lists all
// problems at once; Pass says whether the boot is acceptable.
func Evaluate(p *Policy, in *Input) *Result {
	r := &Result{}
	if err := in.Log.CheckReplay(in.Quoted); err != nil {
		r.add(-1, "replay", false, "%v", err)
		return r // nothing in the log can be trusted
	}
	r.add(-1, "replay", true, "event log replays to the quoted PCRs 0-9")
	ami, ok := p.AMIs[in.AMI]
	if !ok {
		r.add(-1, "ami", false, "no boot references for %s", in.AMI)
		return r
	}

	byPCR := map[uint32][]*eventlog.Event{}
	selfOK := true
	for i := range in.Log.Events {
		e := &in.Log.Events[i]
		if e.Type == eventlog.EvNoAction {
			continue
		}
		byPCR[e.PCR] = append(byPCR[e.PCR], e)
		if d := selfDigest(e); d != nil && !bytes.Equal(d, e.SHA256) {
			selfOK = false
			r.add(int(e.PCR), "event-data", false, "event %d (%s): data does not match its digest", e.Index, eventlog.TypeName(e.Type))
		}
	}
	if selfOK {
		r.add(-1, "event-data", true, "every event whose digest covers its own data matches it")
	}

	// PCR 0: firmware.
	pcr0 := hexs(in.Quoted[0])
	found := ""
	for _, v := range p.FirmwarePCR0 {
		if v.SHA256 == pcr0 {
			found = v.Why
		}
	}
	r.add(0, "firmware", found != "", "PCR 0 %s… %s", pcr0[:16], map[bool]string{true: "is allowed: " + found, false: "is not in the firmware allow-list"}[found != ""])

	// PCRs 2, 3, 6: separator only.
	for _, i := range []uint32{2, 3, 6} {
		evs := byPCR[i]
		ok := len(evs) == 1 && evs[0].Type == eventlog.EvSeparator
		r.add(int(i), "separator-only", ok, "%d event(s)", len(evs))
	}

	checkPCR1(r, byPCR[1], in.RootVolumeID)
	checkPCR4(r, p, byPCR[4], in.Manifest, ami)
	checkPCR5(r, byPCR[5], ami)
	checkPCR7(r, p, byPCR[7])
	checkPCR8(r, p, byPCR[8], ami)
	checkPCR9(r, p, byPCR[9], in.Manifest, ami)
	return r
}

func checkPCR1(r *Result, evs []*eventlog.Event, rootVolume string) {
	var descs []string
	ok := true
	for _, e := range evs {
		switch e.Type {
		case eventlog.EvSeparator:
		case eventlog.EvEFIVariableBoot:
			v, err := e.ParseVariable()
			if err != nil {
				ok = false
				continue
			}
			if strings.HasPrefix(v.Name, "Boot") && v.Name != "BootOrder" {
				d, err := eventlog.LoadOptionDescription(v.Data)
				if err != nil {
					ok = false
					continue
				}
				descs = append(descs, v.Name+"="+d)
			}
		default:
			ok = false
			r.add(1, "boot-variables", false, "unexpected %s event %d", eventlog.TypeName(e.Type), e.Index)
		}
	}
	r.add(1, "boot-variables", ok, "boot options: %s", strings.Join(descs, "; "))
	if rootVolume != "" {
		want := strings.ReplaceAll(rootVolume, "-", "")
		has := false
		for _, d := range descs {
			has = has || strings.Contains(d, want)
		}
		r.add(1, "root-volume", has, "a boot option names this instance's root volume %s", rootVolume)
	}
}

// kernelPath is the file the command line boots, e.g. "/vmlinuz-7.0" -> "/boot/vmlinuz-7.0".
func kernelPath(p *Policy, cmdline string) string {
	f := strings.Fields(cmdline)
	if len(f) == 0 {
		return ""
	}
	path, _ := grubPath(p, f[0])
	return path
}

func checkPCR4(r *Result, p *Policy, evs []*eventlog.Event, idx map[string]manifest.Entry, ami AMI) {
	stages := []struct {
		name  string
		paths []string
	}{
		{"shim", p.EFIChain.Shim},
		{"GRUB", p.EFIChain.Grub},
		{"kernel", []string{kernelPath(p, ami.KernelCmdline)}},
	}
	apps := 0
	for _, e := range evs {
		switch e.Type {
		case eventlog.EvSeparator:
		case eventlog.EvEFIAction:
			s := e.String()
			r.add(4, "boot-action", s == p.BootAction, "%q", s)
		case eventlog.EvEFIBootServicesApp:
			apps++
			if apps > len(stages) {
				r.add(4, "efi-application", false, "event %d %s…: a fourth EFI application", e.Index, hexs(e.SHA256)[:16])
				continue
			}
			st := stages[apps-1]
			var hit []string
			for _, path := range st.paths {
				if m, ok := idx[path]; ok && m.Authenticode != "" && m.Authenticode == hexs(e.SHA256) {
					hit = append(hit, path)
				}
			}
			sort.Strings(hit)
			r.add(4, "efi-application", len(hit) > 0, "%s (event %d) %s… %s", st.name, e.Index, hexs(e.SHA256)[:16],
				map[bool]string{true: "is " + strings.Join(hit, ", ") + " (manifest, Authenticode)",
					false: "is not " + strings.Join(st.paths, " or ") + " of the signed manifest"}[len(hit) > 0])
		default:
			r.add(4, "efi-application", false, "unexpected %s event %d", eventlog.TypeName(e.Type), e.Index)
		}
	}
	r.add(4, "application-count", apps == len(stages), "%d EFI applications started (want shim, GRUB, kernel)", apps)
}

func checkPCR5(r *Result, evs []*eventlog.Event, ami AMI) {
	for _, e := range evs {
		switch e.Type {
		case eventlog.EvEFIGPTEvent:
			r.add(5, "gpt", hexs(e.SHA256) == ami.GPT, "partition table digest %s…", hexs(e.SHA256)[:16])
		case eventlog.EvSeparator:
		case eventlog.EvEFIAction:
			s := e.String()
			ok := s == "Exit Boot Services Invocation" || s == "Exit Boot Services Returned with Success"
			r.add(5, "exit-boot-services", ok, "%q", s)
		default:
			r.add(5, "pcr5-events", false, "unexpected %s event %d", eventlog.TypeName(e.Type), e.Index)
		}
	}
}

func checkPCR7(r *Result, p *Policy, evs []*eventlog.Event) {
	seen := map[string]bool{}
	for _, e := range evs {
		var key string
		switch e.Type {
		case eventlog.EvSeparator:
			continue
		case eventlog.EvEFIVariableDriverConfig, eventlog.EvEFIVariableAuthority:
			v, err := e.ParseVariable()
			if err != nil {
				r.add(7, "secure-boot", false, "event %d: %v", e.Index, err)
				continue
			}
			key = v.Name
			if e.Type == eventlog.EvEFIVariableAuthority {
				key = "authority:" + v.Name
			}
			if v.Name == "SecureBoot" && e.Type == eventlog.EvEFIVariableDriverConfig {
				r.add(7, "secure-boot-enabled", bytes.Equal(v.Data, []byte{1}), "SecureBoot variable = %x", v.Data)
			}
		default:
			r.add(7, "secure-boot", false, "unexpected %s event %d", eventlog.TypeName(e.Type), e.Index)
			continue
		}
		seen[key] = true
		want, known := p.SecureBoot[key]
		r.add(7, "secure-boot", known && want == hexs(e.SHA256), "%s %s", key,
			map[bool]string{true: "matches the reference", false: "differs from the reference"}[known && want == hexs(e.SHA256)])
	}
	for k := range p.SecureBoot {
		if !seen[k] {
			r.add(7, "secure-boot", false, "%s missing from the log", k)
		}
	}
}

func checkPCR8(r *Result, p *Policy, evs []*eventlog.Event, ami AMI) {
	cmdlines := 0
	other := 0
	for _, e := range evs {
		if e.Type != eventlog.EvIPL {
			r.add(8, "grub-commands", false, "unexpected %s event %d", eventlog.TypeName(e.Type), e.Index)
			continue
		}
		s := e.String()
		switch {
		case strings.HasPrefix(s, "kernel_cmdline: "):
			cmdlines++
			cl := strings.TrimPrefix(s, "kernel_cmdline: ")
			r.add(8, "kernel-cmdline", cl == ami.KernelCmdline, "%q", cl)
			for _, tok := range p.RequiredCmdline {
				has := false
				for _, f := range strings.Fields(cl) {
					has = has || f == tok
				}
				if !has {
					r.add(8, "kernel-cmdline", false, "missing %q", tok)
				}
			}
		case strings.HasPrefix(s, "grub_cmd: "):
			other++
		default:
			r.add(8, "grub-commands", false, "event %d is neither a GRUB command nor the kernel command line", e.Index)
		}
	}
	r.add(8, "grub-commands", cmdlines == 1, "%d GRUB commands, %d kernel command line(s)", other, cmdlines)
}

// grubPath maps a GRUB path such as "(hd0,gpt16)/grub/grub.cfg" or
// "/vmlinuz-7.0" to the path in the node's file system.
func grubPath(p *Policy, s string) (string, bool) {
	if strings.HasPrefix(s, "(") {
		i := strings.Index(s, ")")
		if i < 0 {
			return "", false
		}
		mnt, ok := p.GrubPartitions[s[:i+1]]
		if !ok {
			return "", false
		}
		return strings.TrimSuffix(mnt, "/") + s[i+1:], true
	}
	if strings.HasPrefix(s, "/") {
		return strings.TrimSuffix(p.GrubRoot, "/") + s, true
	}
	return "", false
}

// LoadOptionsDigest is what the kernel's EFI stub measures for its load
// options: GRUB passes "BOOT_IMAGE=" and the command line, in UTF-16LE, with
// no terminator. Checked against a NitroTPM boot (event e3fdea40…).
func LoadOptionsDigest(cmdline string) []byte {
	u := utf16.Encode([]rune("BOOT_IMAGE=" + cmdline))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		b[2*i], b[2*i+1] = byte(c), byte(c>>8)
	}
	return sum(b)
}

func checkPCR9(r *Result, p *Policy, evs []*eventlog.Event, idx map[string]manifest.Entry, ami AMI) {
	initrds, opts := 0, 0
	mutable := map[string]bool{}
	for _, m := range p.MutableFiles {
		mutable[m] = true
	}
	loaded := map[string]string{} // digest -> path, files GRUB loaded and the manifest vouches for
	files, bad := 0, 0
	for _, e := range evs {
		switch e.Type {
		case eventlog.EvIPL:
			files++
			path, ok := grubPath(p, e.String())
			if !ok {
				bad++
				r.add(9, "grub-file", false, "event %d: cannot map %q to a path", e.Index, e.String())
				continue
			}
			if mutable[path] {
				continue
			}
			m, ok := idx[path]
			if !ok || m.Type != "file" || m.SHA256 != hexs(e.SHA256) {
				bad++
				r.add(9, "grub-file", false, "%s %s… does not match the signed manifest", path, hexs(e.SHA256)[:16])
				continue
			}
			loaded[hexs(e.SHA256)] = path
		case eventlog.EvEventTag:
			// The kernel's EFI stub tags what it received: the initrd and its
			// load options (the command line, already checked in PCR 8).
			switch {
			case bytes.Contains(e.Data, []byte("LOADED_IMAGE::LoadOptions")):
				opts++
				ok := bytes.Equal(e.SHA256, LoadOptionsDigest(ami.KernelCmdline))
				r.add(9, "load-options", ok, "kernel received %s", map[bool]string{true: "the expected command line", false: "a command line other than the expected one"}[ok])
			case bytes.Contains(e.Data, []byte("Linux initrd")):
				initrds++
				path, ok := loaded[hexs(e.SHA256)]
				r.add(9, "initrd", ok, "kernel received %s", map[bool]string{true: path + " (loaded by GRUB, in the manifest)", false: "an initrd GRUB did not load from the manifest"}[ok])
				if ok {
					r.Initrd = path
				}
			default:
				bad++
				r.add(9, "grub-file", false, "unknown event tag %d", e.Index)
			}
		default:
			bad++
			r.add(9, "grub-file", false, "unexpected %s event %d", eventlog.TypeName(e.Type), e.Index)
		}
	}
	r.add(9, "kernel-tags", initrds == 1 && opts == 1, "%d initrd tag(s), %d load-options tag(s)", initrds, opts)
	r.add(9, "grub-files", bad == 0, "%d file loads, all in the signed manifest except %v", files, p.MutableFiles)
}
