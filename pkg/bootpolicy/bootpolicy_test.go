package bootpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"nodetrust/pkg/eventlog"
	"nodetrust/pkg/manifest"
)

// The real log of a NitroTPM boot of ami-07deef95f949d1d5d (instance
// i-09e07c767c24ddd6a, root volume vol-0af96f3cd779bc1e4), shared with
// pkg/eventlog.
const (
	logFile = "../eventlog/testdata/nitro-ami-07deef95.bin"
	expFile = "../eventlog/testdata/nitro-ami-07deef95.expected.json"
	testAMI = "ami-07deef95f949d1d5d"
	rootVol = "vol-0af96f3cd779bc1e4"
)

func readLog(t *testing.T) ([]byte, map[int][]byte) {
	t.Helper()
	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(expFile)
	if err != nil {
		t.Fatal(err)
	}
	var exp struct {
		PCRs map[string]string `json:"pcrs"`
	}
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Fatal(err)
	}
	q := map[int][]byte{}
	for k, v := range exp.PCRs {
		i, _ := strconv.Atoi(k)
		q[i], _ = hex.DecodeString(v)
	}
	return raw, q
}

func parse(t *testing.T, raw []byte) *eventlog.Log {
	t.Helper()
	l, err := eventlog.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// bootManifest is the /boot part of the AMI's manifest. File hashes of the
// kernel, initrd, /boot/grub/grub.cfg and the EFI files come from sha256sum
// on the node (fetch-eventlog.sh boot-files.txt); the Authenticode hashes
// from manifest.py run on the Ubuntu archive packages (shim-signed 1.58,
// grub-efi-amd64-signed 1.202.5, linux-image-7.0.0-1017-aws), which are
// byte-identical to the AMI's files.
func bootManifest() map[string]manifest.Entry {
	f := func(path, sha, ac string) manifest.Entry {
		return manifest.Entry{Path: path, Type: "file", SHA256: sha, Authenticode: ac}
	}
	const (
		shimAC   = "724de6844dd0fe618ba5776c7bca0728be38a6544e24e44ef259b987b7abce80"
		grubAC   = "4caffb530989433f184353c48d8150fcdce6037933ab129249f50f0068cf1815"
		kernelAC = "43fe96482536d1048bf3a3cb4bf306fb22f7cd12f26950d5185bb18fb3039d1e"
		shimSHA  = "6fe6e1bcbe6cf6baec8e056d40361ca1aa715cc04ddcc2855351de060b84350b"
	)
	es := []manifest.Entry{
		f("/boot/efi/EFI/BOOT/BOOTX64.EFI", shimSHA, shimAC),
		f("/boot/efi/EFI/ubuntu/shimx64.efi", shimSHA, shimAC),
		f("/boot/efi/EFI/ubuntu/grubx64.efi", "a831af01e4fb5e3c9457120e1d08ea13d98a0a47b62728c284b7f502d535965c", grubAC),
		f("/boot/vmlinuz-7.0.0-1017-aws", "cab0d1e698f1840109aff4fb2a00c3bc3fb304aa48098773a9b81b3cb3996e6e", kernelAC),
		f("/boot/initrd.img-7.0.0-1017-aws", "33e07f271b843141a5a8b5925b2a40ee31999cca148541f30f40d910cf585374", ""),
		f("/boot/grub/grub.cfg", "03a187d017483a99f19ba973a486a3c8d9aad52d16d5c6c38d38056fda73dae4", ""),
		// Not in boot-files.txt; values as the boot measured them.
		f("/boot/efi/EFI/ubuntu/grub.cfg", "01a550946685e21e873121bc2d23b089eabd833945ea78c6ed554e97d4c2c3ed", ""),
		f("/boot/grub/x86_64-efi/command.lst", "aef695413d1a1b9eaff753a15512d0ba79e23e5524033eec20c7a1c7c20eb1c4", ""),
		f("/boot/grub/x86_64-efi/fs.lst", "32fc7f5de8c0a5dc0b1e7eb609ca31a77eb3475539e1d97a4543dca1b9b26c57", ""),
		f("/boot/grub/x86_64-efi/crypto.lst", "1b766f38a94927fe9b7bc1e809f0363e778e14c601e800faea271a2e75d3fc43", ""),
		f("/boot/grub/x86_64-efi/terminal.lst", "46f888c52f36baf9b62d60bc8d06426a314aad5a0ff86a4362a91c2512a1df9c", ""),
		f("/boot/grub/x86_64-efi/bli.mod", "b49a7fd5edc02f168f0de51309313278dc2347c0f83a5cbedcb8974790a5e7e8", ""),
		f("/boot/microcode.cpio", "85548ac86ecc5dbd1b587062d765e298a074ac972d88d0e6a0c918d7ffbf145b", ""),
		f("/boot/grub/grubenv", "0000000000000000000000000000000000000000000000000000000000000000", ""),
	}
	m := map[string]manifest.Entry{}
	for _, e := range es {
		m[e.Path] = e
	}
	return m
}

func refPolicy(t *testing.T, l *eventlog.Log) *Policy {
	t.Helper()
	p, err := Reference(nil, l, testAMI, "NitroTPM firmware seen on the golden AMI probe")
	if err != nil {
		t.Fatal(err)
	}
	// Round trip through JSON, as the policy is stored.
	b, _ := json.Marshal(p)
	p, err = LoadPolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func input(l *eventlog.Log, q map[int][]byte) *Input {
	return &Input{Log: l, Quoted: q, Manifest: bootManifest(), AMI: testAMI, RootVolumeID: rootVol}
}

func failures(r *Result) []string {
	var out []string
	for _, f := range r.Findings {
		if !f.OK {
			out = append(out, f.Check+": "+f.Detail)
		}
	}
	return out
}

func TestRealBootPasses(t *testing.T) {
	raw, q := readLog(t)
	l := parse(t, raw)
	r := Evaluate(refPolicy(t, l), input(l, q))
	if !r.Pass() {
		t.Fatalf("real boot failed:\n%s", strings.Join(failures(r), "\n"))
	}
	if r.Initrd != "/boot/microcode.cpio" {
		t.Errorf("initrd = %q", r.Initrd)
	}
	for _, f := range r.Findings {
		t.Logf("PCR %2d %-20s %s", f.PCR, f.Check, f.Detail)
	}
	// What a reviewer reads in the generated policy.
	p := refPolicy(t, l)
	if p.BootAction != "Calling EFI Application from Boot Option" {
		t.Errorf("reference: %+v", p)
	}
	for _, k := range []string{"SecureBoot", "PK", "KEK", "db", "dbx", "authority:db", "authority:SbatLevel", "authority:MokListRT"} {
		if p.SecureBoot[k] == "" {
			t.Errorf("reference lacks %s", k)
		}
	}
}

func expectFail(t *testing.T, r *Result, check string) {
	t.Helper()
	if r.Pass() {
		t.Fatalf("passed, want a %s failure", check)
	}
	for _, f := range r.Findings {
		if !f.OK && f.Check == check {
			return
		}
	}
	t.Fatalf("no %s failure; failures:\n%s", check, strings.Join(failures(r), "\n"))
}

func TestWrongInstanceVolume(t *testing.T) {
	raw, q := readLog(t)
	l := parse(t, raw)
	in := input(l, q)
	in.RootVolumeID = "vol-0123456789abcdef0"
	expectFail(t, Evaluate(refPolicy(t, l), in), "root-volume")
}

func TestManifestMismatch(t *testing.T) {
	raw, q := readLog(t)
	l := parse(t, raw)
	p := refPolicy(t, l)
	cases := map[string]struct {
		path  string
		edit  func(*manifest.Entry)
		check string
	}{
		"other kernel file": {"/boot/vmlinuz-7.0.0-1017-aws", func(e *manifest.Entry) { e.SHA256 = strings.Repeat("ab", 32) }, "grub-file"},
		"grub.cfg missing":  {"/boot/grub/grub.cfg", nil, "grub-file"},
		"unsigned shim":     {"/boot/efi/EFI/ubuntu/shimx64.efi", func(e *manifest.Entry) { e.Authenticode = "" }, ""},
		"other GRUB image":  {"/boot/efi/EFI/ubuntu/grubx64.efi", func(e *manifest.Entry) { e.Authenticode = strings.Repeat("cd", 32) }, "efi-application"},
		"other microcode":   {"/boot/microcode.cpio", func(e *manifest.Entry) { e.SHA256 = strings.Repeat("ef", 32) }, "initrd"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			in := input(l, q)
			if c.edit == nil {
				delete(in.Manifest, c.path)
			} else {
				e := in.Manifest[c.path]
				c.edit(&e)
				in.Manifest[c.path] = e
			}
			r := Evaluate(p, in)
			if c.check == "" {
				// The shim is also BOOTX64.EFI, so it is still vouched for.
				if !r.Pass() {
					t.Fatalf("failed: %v", failures(r))
				}
				return
			}
			expectFail(t, r, c.check)
		})
	}
}

// TestEFIChainOrder: PCR 4 must be shim, then GRUB, then the kernel the
// command line names. Signed images that are in the manifest but are not
// that stage (MokManager, another kernel) must not pass.
func TestEFIChainOrder(t *testing.T) {
	raw, _ := readLog(t)
	ref := refPolicy(t, parse(t, raw))
	app := func(n int) func(e *eventlog.Event) bool { // the n-th EFI application
		i := 0
		return func(e *eventlog.Event) bool {
			if e.Type != eventlog.EvEFIBootServicesApp {
				return false
			}
			i++
			return i == n
		}
	}
	mokAC, _ := hex.DecodeString(strings.Repeat("8a", 32))
	withMok := func(in *Input) {
		in.Manifest["/boot/efi/EFI/ubuntu/mmx64.efi"] = manifest.Entry{Path: "/boot/efi/EFI/ubuntu/mmx64.efi", Type: "file",
			SHA256: strings.Repeat("11", 32), Authenticode: hex.EncodeToString(mokAC)}
	}

	t.Run("MokManager instead of GRUB", func(t *testing.T) {
		l, q := rewrite(t, raw, app(2), nil, mokAC)
		in := input(l, q)
		withMok(in)
		expectFail(t, Evaluate(ref, in), "efi-application")
	})
	t.Run("shim and GRUB swapped", func(t *testing.T) {
		l := parse(t, raw)
		var a, b *eventlog.Event
		for i := range l.Events {
			if l.Events[i].Type == eventlog.EvEFIBootServicesApp {
				if a == nil {
					a = &l.Events[i]
				} else if b == nil {
					b = &l.Events[i]
				}
			}
		}
		a.SHA256, b.SHA256 = b.SHA256, a.SHA256
		q := map[int][]byte{}
		for k, v := range l.Replay() {
			q[int(k)] = v
		}
		expectFail(t, Evaluate(ref, input(l, q)), "efi-application")
	})
	t.Run("signed kernel the command line does not name", func(t *testing.T) {
		_, q := readLog(t)
		in := input(parse(t, raw), q)
		k := in.Manifest["/boot/vmlinuz-7.0.0-1017-aws"]
		in.Manifest["/boot/vmlinuz-6.8.0-old"] = manifest.Entry{Path: "/boot/vmlinuz-6.8.0-old", Type: "file", SHA256: k.SHA256, Authenticode: k.Authenticode}
		k.Authenticode = ""
		in.Manifest["/boot/vmlinuz-7.0.0-1017-aws"] = k
		expectFail(t, Evaluate(ref, in), "efi-application")
	})
	t.Run("old policy without efi_boot_chain", func(t *testing.T) {
		b, _ := json.Marshal(ref)
		var m map[string]any
		json.Unmarshal(b, &m)
		delete(m, "efi_boot_chain")
		b, _ = json.Marshal(m)
		if _, err := LoadPolicy(b); err == nil {
			t.Fatal("policy without efi_boot_chain accepted")
		}
	})
}

func TestPolicyMismatch(t *testing.T) {
	raw, q := readLog(t)
	l := parse(t, raw)
	cases := map[string]struct {
		edit  func(*Policy)
		check string
	}{
		"unknown firmware": {func(p *Policy) { p.FirmwarePCR0 = []Value{{SHA256: strings.Repeat("00", 32), Why: "other"}} }, "firmware"},
		"other db":         {func(p *Policy) { p.SecureBoot["db"] = strings.Repeat("00", 32) }, "secure-boot"},
		"extra key":        {func(p *Policy) { p.SecureBoot["authority:extra"] = strings.Repeat("00", 32) }, "secure-boot"},
		"other cmdline": {func(p *Policy) {
			a := p.AMIs[testAMI]
			a.KernelCmdline = strings.Replace(a.KernelCmdline, " lockdown=integrity", "", 1)
			p.AMIs[testAMI] = a
		}, "kernel-cmdline"},
		"cmdline lacks a required option": {func(p *Policy) { p.RequiredCmdline = append(p.RequiredCmdline, "module.sig_enforce=1") }, "kernel-cmdline"},
		"other disk": {func(p *Policy) {
			a := p.AMIs[testAMI]
			a.GPT = strings.Repeat("11", 32)
			p.AMIs[testAMI] = a
		}, "gpt"},
		"grubenv not mutable": {func(p *Policy) { p.MutableFiles = nil }, "grub-file"},
		"wrong partition map": {func(p *Policy) { p.GrubPartitions = map[string]string{"(hd0,gpt16)": "/boot"} }, "grub-file"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := refPolicy(t, l)
			c.edit(p)
			expectFail(t, Evaluate(p, input(l, q)), c.check)
		})
	}
	t.Run("unknown AMI", func(t *testing.T) {
		in := input(l, q)
		in.AMI = "ami-0000"
		expectFail(t, Evaluate(refPolicy(t, l), in), "ami")
	})
}

// rewrite rebuilds a log with one event changed (data and digest), so it
// still replays, and returns the new log with the PCRs it replays to: the
// "attacker controls the boot and the log" case, where only the checks on
// content can catch it.
func rewrite(t *testing.T, raw []byte, match func(e *eventlog.Event) bool, data []byte, digest []byte) (*eventlog.Log, map[int][]byte) {
	t.Helper()
	l := parse(t, raw)
	n := 0
	for i := range l.Events {
		e := &l.Events[i]
		if match(e) {
			e.Data = data
			e.SHA256 = digest
			n++
		}
	}
	if n == 0 {
		t.Fatal("no event matched")
	}
	q := map[int][]byte{}
	for k, v := range l.Replay() {
		q[int(k)] = v
	}
	for i := 0; i <= 9; i++ {
		if q[i] == nil {
			q[i] = make([]byte, 32)
		}
	}
	return l, q
}

func TestForgedBoots(t *testing.T) {
	raw, _ := readLog(t)
	ref := refPolicy(t, parse(t, raw))
	s := func(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

	t.Run("other kernel command line, honestly measured", func(t *testing.T) {
		cl := ref.AMIs[testAMI].KernelCmdline + " ima_appraise=off"
		l, q := rewrite(t, raw, func(e *eventlog.Event) bool {
			return e.PCR == 8 && strings.HasPrefix(e.String(), "kernel_cmdline: ")
		}, append([]byte("kernel_cmdline: "+cl), 0), s([]byte(cl)))
		expectFail(t, Evaluate(ref, input(l, q)), "kernel-cmdline")
	})
	t.Run("log text does not match its digest", func(t *testing.T) {
		// Keep the measured digest but claim the expected text.
		l, q := rewrite(t, raw, func(e *eventlog.Event) bool {
			return e.PCR == 8 && strings.HasPrefix(e.String(), "kernel_cmdline: ")
		}, append([]byte("kernel_cmdline: "+ref.AMIs[testAMI].KernelCmdline), 0), s([]byte("init=/bin/sh")))
		expectFail(t, Evaluate(ref, input(l, q)), "event-data")
	})
	t.Run("kernel got other load options", func(t *testing.T) {
		l, q := rewrite(t, raw, func(e *eventlog.Event) bool {
			return e.Type == eventlog.EvEventTag && bytes.Contains(e.Data, []byte("LoadOptions"))
		}, l0(raw), LoadOptionsDigest(ref.AMIs[testAMI].KernelCmdline+" init=/bin/sh"))
		expectFail(t, Evaluate(ref, input(l, q)), "load-options")
	})
	t.Run("Secure Boot off", func(t *testing.T) {
		l := parse(t, raw)
		var data []byte
		for _, e := range l.Events {
			if e.PCR == 7 && e.Type == eventlog.EvEFIVariableDriverConfig {
				if v, _ := e.ParseVariable(); v.Name == "SecureBoot" {
					data = append([]byte(nil), e.Data...)
					data[len(data)-1] = 0
				}
			}
		}
		l, q := rewrite(t, raw, func(e *eventlog.Event) bool {
			v, err := e.ParseVariable()
			return e.PCR == 7 && err == nil && v.Name == "SecureBoot"
		}, data, s(data))
		expectFail(t, Evaluate(ref, input(l, q)), "secure-boot-enabled")
	})
	t.Run("extra EFI application", func(t *testing.T) {
		// Turn the PCR 4 boot action into a fourth application load.
		l, q := rewrite(t, raw, func(e *eventlog.Event) bool {
			return e.PCR == 4 && e.Type == eventlog.EvEFIAction
		}, nil, s([]byte("evil.efi")))
		for i := range l.Events {
			if l.Events[i].PCR == 4 && l.Events[i].Data == nil {
				l.Events[i].Type = eventlog.EvEFIBootServicesApp
			}
		}
		expectFail(t, Evaluate(ref, input(l, q)), "efi-application")
	})
	t.Run("log does not match quote", func(t *testing.T) {
		_, q := readLog(t)
		l, _ := rewrite(t, raw, func(e *eventlog.Event) bool {
			return e.PCR == 9 && e.String() == "/microcode.cpio"
		}, []byte("/microcode.cpio\x00"), s([]byte("other")))
		r := Evaluate(ref, input(l, q))
		expectFail(t, r, "replay")
		if len(r.Findings) != 1 {
			t.Errorf("checks ran on an unreplayable log: %d findings", len(r.Findings))
		}
	})
}

// l0 returns the LoadOptions tag data from the real log.
func l0(raw []byte) []byte {
	l, _ := eventlog.Parse(raw)
	for _, e := range l.Events {
		if e.Type == eventlog.EvEventTag && bytes.Contains(e.Data, []byte("LoadOptions")) {
			return e.Data
		}
	}
	return nil
}

func TestLoadOptionsDigest(t *testing.T) {
	raw, _ := readLog(t)
	ref := refPolicy(t, parse(t, raw))
	want, _ := hex.DecodeString("e3fdea407aa48d77f8db76c79b272fab138ba94f1be84478811e157a2aa1543c")
	if got := LoadOptionsDigest(ref.AMIs[testAMI].KernelCmdline); !bytes.Equal(got, want) {
		t.Fatalf("got %x", got)
	}
}

func TestReferenceAddsAMI(t *testing.T) {
	raw, _ := readLog(t)
	l := parse(t, raw)
	p := refPolicy(t, l)
	p2, err := Reference(p, l, "ami-new", "same firmware")
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.AMIs) != 2 || len(p2.FirmwarePCR0) != 1 || len(p.AMIs) != 1 {
		t.Fatalf("amis %d firmware %d (base amis %d)", len(p2.AMIs), len(p2.FirmwarePCR0), len(p.AMIs))
	}
	p.SecureBoot["db"] = strings.Repeat("00", 32)
	if _, err := Reference(p, l, "ami-x", ""); err == nil {
		t.Fatal("Secure Boot change accepted")
	}
	if _, err := LoadPolicy([]byte(`{"firmware_pcr0":[],"amis":{}}`)); err == nil {
		t.Fatal("empty policy accepted")
	}
	if _, err := LoadPolicy([]byte(`{"surprise":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}
