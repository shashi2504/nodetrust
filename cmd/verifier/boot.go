package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"nodetrust/pkg/bootpolicy"
	"nodetrust/pkg/eventlog"
	"nodetrust/pkg/manifest"
)

// bootReference writes a boot policy (or adds an AMI to one) from the event
// log of a trusted boot (Phase 4, step 4.1). The output is for review: it
// pins what that boot measured, nothing more.
func bootReference(args []string) int {
	fs := flag.NewFlagSet("boot-reference", flag.ContinueOnError)
	logPath := fs.String("event-log", "", "event log of a trusted boot (eventlog.bin from attest-node)")
	ami := fs.String("ami", "", "AMI that instance was launched from")
	base := fs.String("base", "", "existing boot policy to add the AMI to (optional)")
	why := fs.String("firmware-why", "", "why the firmware (PCR 0) value is trusted, for the review")
	out := fs.String("out", "", "boot policy to write")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *logPath == "" || *ami == "" || *out == "" || *why == "" {
		fmt.Fprintln(os.Stderr, "boot-reference: -event-log, -ami, -firmware-why and -out are required")
		return 2
	}
	raw, err := os.ReadFile(*logPath)
	if err != nil {
		return fail(err)
	}
	l, err := eventlog.Parse(raw)
	if err != nil {
		return fail(err)
	}
	var bp *bootpolicy.Policy
	if *base != "" {
		b, err := os.ReadFile(*base)
		if err != nil {
			return fail(err)
		}
		if bp, err = bootpolicy.LoadPolicy(b); err != nil {
			return fail(err)
		}
	}
	p, err := bootpolicy.Reference(bp, l, *ami, *why)
	if err != nil {
		return fail(err)
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		return fail(err)
	}
	fmt.Printf("OK wrote %s: %d firmware value(s), %d Secure Boot digests, %d AMI(s); review before use\n",
		*out, len(p.FirmwarePCR0), len(p.SecureBoot), len(p.AMIs))
	return 0
}

// readPCRs reads the PCR lines of a pcrs.txt written by attest-node from a
// verified quote.
func readPCRs(path string) (map[int][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	q := map[int][]byte{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) != 3 || fl[0] != "PCR" {
			continue
		}
		i, err := strconv.Atoi(fl[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %q", path, sc.Text())
		}
		if q[i], err = hex.DecodeString(fl[2]); err != nil || len(q[i]) != 32 {
			return nil, fmt.Errorf("%s: %q", path, sc.Text())
		}
	}
	return q, sc.Err()
}

// checkBoot checks a boot event log against the boot policy and the AMI's
// signed manifest. The PCRs come from attest-node's pcrs.txt (a verified
// quote); the log must replay to them before anything in it is used.
func checkBoot(args []string) int {
	fs := flag.NewFlagSet("check-boot", flag.ContinueOnError)
	tf := addTrustFlags(fs)
	policyPath := fs.String("boot-policy", "", "boot policy (boot-policy.json)")
	logPath := fs.String("event-log", "", "eventlog.bin from attest-node")
	pcrPath := fs.String("pcrs", "", "pcrs.txt from attest-node (same run)")
	vol := fs.String("root-volume", "", "the instance's root EBS volume, from EC2")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" || *logPath == "" || *pcrPath == "" || *vol == "" {
		fmt.Fprintln(os.Stderr, "check-boot: -boot-policy, -event-log, -pcrs and -root-volume are required with the verify-manifest flags")
		return 2
	}
	rawManifest, err := loadTrusted(tf, true)
	if err != nil {
		return fail(err)
	}
	idx, err := manifest.Index(rawManifest)
	if err != nil {
		return fail(err)
	}
	pb, err := os.ReadFile(*policyPath)
	if err != nil {
		return fail(err)
	}
	p, err := bootpolicy.LoadPolicy(pb)
	if err != nil {
		return fail(err)
	}
	raw, err := os.ReadFile(*logPath)
	if err != nil {
		return fail(err)
	}
	l, err := eventlog.Parse(raw)
	if err != nil {
		return fail(err)
	}
	q, err := readPCRs(*pcrPath)
	if err != nil {
		return fail(err)
	}
	r := bootpolicy.Evaluate(p, &bootpolicy.Input{Log: l, Quoted: q, Manifest: idx, AMI: *tf.ami, RootVolumeID: *vol})
	var buf bytes.Buffer
	for _, f := range r.Findings {
		state := "OK"
		if !f.OK {
			state = "FAIL"
		}
		pcr := "   "
		if f.PCR >= 0 {
			pcr = fmt.Sprintf("%2d ", f.PCR)
		}
		fmt.Fprintf(&buf, "%-4s boot pcr%s%-20s %s\n", state, pcr, f.Check, f.Detail)
	}
	fmt.Print(buf.String())
	if !r.Pass() {
		fmt.Println("FAIL boot does not match the boot policy")
		return 1
	}
	fmt.Println("OK boot matches the boot policy and the signed manifest")
	return 0
}
