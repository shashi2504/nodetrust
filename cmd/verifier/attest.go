package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"nodetrust/pkg/attest"
	"nodetrust/pkg/verifier"
)

// attestNode enrolls an agent over mTLS (or reuses an enrolled record) and
// checks a quote (Phase 3, step 3.3).
func attestNode(args []string) int {
	fs := flag.NewFlagSet("attest-node", flag.ContinueOnError)
	addr := fs.String("addr", "", "agent address HOST:PORT")
	instance := fs.String("instance", "", "instance ID, from the cloud API")
	cloudEK := fs.String("cloud-ek", "", "file with the EK from ec2:GetInstanceTpmEkPub (base64 DER)")
	certPath := fs.String("cert", "", "verifier client certificate (PEM)")
	keyPath := fs.String("key", "", "verifier client key (PEM)")
	outDir := fs.String("out", "", "directory for enrolled.json and pcrs.txt")
	quotes := fs.Int("quotes", 2, "quotes to take after enrolling")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *addr == "" || *instance == "" || *cloudEK == "" || *certPath == "" || *keyPath == "" || *outDir == "" {
		fmt.Fprintln(os.Stderr, "attest-node: all flags are required")
		return 2
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		return fail(err)
	}
	b, err := os.ReadFile(*cloudEK)
	if err != nil {
		return fail(err)
	}
	ek, err := attest.ParseCloudEK(string(b))
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		return fail(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := verifier.NewClient(*addr, cert)
	start := time.Now()
	e, err := c.Enroll(ctx, *instance, ek)
	if err != nil {
		return fail(fmt.Errorf("enroll %s: %w", *addr, err))
	}
	fmt.Printf("OK enrolled %s over mTLS in %.1fs: EK matches the cloud, TPM released the secret\n",
		*instance, time.Since(start).Seconds())
	if err := writeJSON(filepath.Join(*outDir, "enrolled.json"), e, 0o644); err != nil {
		return fail(err)
	}

	var last *verifier.QuoteResult
	for i := 1; i <= *quotes; i++ {
		start = time.Now()
		r, err := c.Quote(ctx, e, verifier.QuoteOptions{}) // the whole log and the event log every time
		if err != nil {
			return fail(fmt.Errorf("quote %d: %w", i, err))
		}
		fmt.Printf("OK quote %d in %.1fs: AK signature, TLS-bound nonce, PCR digest; IMA log replays (%d attested, %d after)\n",
			i, time.Since(start).Seconds(), r.IMA.Attested, r.IMA.After)
		if r.BootLog != nil {
			fmt.Printf("OK boot event log replays to the quoted PCRs 0-9 (%d events)\n", len(r.BootLog.Events))
		} else {
			fmt.Println("WARN agent sent no boot event log")
		}
		if last != nil && r.Quote.ResetCount != last.Quote.ResetCount {
			fmt.Printf("WARN resetCount changed between quotes (%d -> %d): the node rebooted\n", last.Quote.ResetCount, r.Quote.ResetCount)
		}
		last = r
	}
	if last.BootLog != nil {
		if err := os.WriteFile(filepath.Join(*outDir, "eventlog.bin"), last.BootLogRaw, 0o644); err != nil {
			return fail(err)
		}
	}
	f, err := os.Create(filepath.Join(*outDir, "pcrs.txt"))
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	fmt.Fprintf(f, "INFO TPM resetCount=%d restartCount=%d clock=%dms safe=%v\n",
		last.Quote.ResetCount, last.Quote.RestartCount, last.Quote.Clock, last.Quote.Safe)
	idx := make([]int, 0, len(last.PCRs))
	for i := range last.PCRs {
		idx = append(idx, i)
	}
	sort.Ints(idx)
	for _, i := range idx {
		fmt.Fprintf(f, "PCR %2d %x\n", i, last.PCRs[i])
	}
	return 0
}
