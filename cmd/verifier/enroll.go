package main

// Step 3.2 subcommands: enrollment and quote checks with files, driven by
// infra/phase3/enroll-node.sh. Phase 4 serves the same logic (pkg/verifier).

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"nodetrust/pkg/attest"
	"nodetrust/pkg/protocol"
	"nodetrust/pkg/verifier"
)

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer zr.Close()
		r = zr
	}
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(path string, v any, mode os.FileMode) error {
	b, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), mode)
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "FAIL", err)
	return 1
}

func enrollChallenge(args []string) int {
	fs := flag.NewFlagSet("enroll-challenge", flag.ContinueOnError)
	instance := fs.String("instance", "", "instance ID, as the verifier knows it")
	cloudEK := fs.String("cloud-ek", "", "file with the EK from ec2:GetInstanceTpmEkPub (base64 DER)")
	reqPath := fs.String("request", "", "agent EnrollRequest (JSON)")
	chOut := fs.String("challenge-out", "", "where to write the Challenge")
	pendOut := fs.String("pending-out", "", "where to write the verifier's private state (holds the secret)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *instance == "" || *cloudEK == "" || *reqPath == "" || *chOut == "" || *pendOut == "" {
		fmt.Fprintln(os.Stderr, "enroll-challenge: all flags are required")
		return 2
	}
	b, err := os.ReadFile(*cloudEK)
	if err != nil {
		return fail(err)
	}
	ek, err := attest.ParseCloudEK(string(b))
	if err != nil {
		return fail(err)
	}
	var req protocol.EnrollRequest
	if err := readJSON(*reqPath, &req); err != nil {
		return fail(fmt.Errorf("request: %w", err))
	}
	if req.InstanceID != "" && req.InstanceID != *instance {
		fmt.Printf("WARN agent says it is %s; using %s from the cloud API\n", req.InstanceID, *instance)
	}
	ch, pending, err := verifier.NewChallenge(*instance, ek, &req)
	if err != nil {
		return fail(err)
	}
	if err := writeJSON(*pendOut, pending, 0o600); err != nil {
		return fail(err)
	}
	if err := writeJSON(*chOut, ch, 0o644); err != nil {
		return fail(err)
	}
	fmt.Println("OK EK in the agent's request is the TCG RSA-2048 EK and equals the cloud's EK for", *instance)
	fmt.Println("OK AK is a restricted, fixedTPM signing key; credential made for its name")
	return 0
}

func enrollFinish(args []string) int {
	fs := flag.NewFlagSet("enroll-finish", flag.ContinueOnError)
	pendPath := fs.String("pending", "", "verifier state from enroll-challenge")
	respPath := fs.String("response", "", "agent ChallengeResponse (JSON)")
	out := fs.String("out", "", "where to write the Enrolled record")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var p verifier.Pending
	if err := readJSON(*pendPath, &p); err != nil {
		return fail(err)
	}
	var resp protocol.ChallengeResponse
	if err := readJSON(*respPath, &resp); err != nil {
		return fail(err)
	}
	e, err := verifier.Finish(&p, &resp, time.Now())
	if err != nil {
		return fail(err)
	}
	if err := writeJSON(*out, e, 0o644); err != nil {
		return fail(err)
	}
	fmt.Printf("OK enrolled %s: TPM released the secret, AK %s… bound to EK %s…\n", e.InstanceID, e.AKName[:20], e.EKSHA256[:16])
	return 0
}

func checkQuote(args []string) int {
	fs := flag.NewFlagSet("check-quote", flag.ContinueOnError)
	enrPath := fs.String("enrolled", "", "Enrolled record")
	nonceHex := fs.String("nonce", "", "the nonce sent with the quote request (hex)")
	qPath := fs.String("quote", "", "agent QuoteResponse (JSON or .json.gz)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	var e verifier.Enrolled
	if err := readJSON(*enrPath, &e); err != nil {
		return fail(err)
	}
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil {
		return fail(fmt.Errorf("nonce: %w", err))
	}
	var resp protocol.QuoteResponse
	if err := readJSON(*qPath, &resp); err != nil {
		return fail(fmt.Errorf("quote: %w", err))
	}
	r, err := verifier.CheckQuote(&e, nonce, &resp, nil)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("OK quote signed by the enrolled AK of %s, nonce matches, PCRs %v match the signed digest\n",
		e.InstanceID, r.Quote.Selection[0].PCRs)
	fmt.Printf("OK IMA log replays to the quoted PCR 10: %d attested entries, %d appended after the quote\n",
		r.IMA.Attested, r.IMA.After)
	if r.BootLog != nil {
		fmt.Printf("OK boot event log replays to the quoted PCRs 0-9 (%d events)\n", len(r.BootLog.Events))
	}
	fmt.Printf("INFO TPM resetCount=%d restartCount=%d clock=%dms safe=%v\n",
		r.Quote.ResetCount, r.Quote.RestartCount, r.Quote.Clock, r.Quote.Safe)
	idx := make([]int, 0, len(r.PCRs))
	for i := range r.PCRs {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		fmt.Printf("PCR %2d %x\n", i, r.PCRs[i])
	}
	return 0
}
