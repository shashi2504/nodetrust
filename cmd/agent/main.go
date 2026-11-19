// Command agent runs on every worker. It answers verifier challenges with
// NitroTPM quotes and the IMA log, and decides nothing itself.
//
// Step 3.2 subcommands (driven over SSM by infra/phase3/enroll-node.sh; in
// Phase 4 the same operations are served over mTLS):
//
//	agent enroll-request                 print an EnrollRequest (EK and AK public areas)
//	agent activate -challenge B64JSON    activate a Challenge, print the ChallengeResponse
//	agent quote -nonce HEX -out FILE     write a gzipped QuoteResponse with the IMA log
//
// Step 3.3, the service the golden AMI starts at boot:
//
//	agent serve [-listen :9443] [-verifier-ca FILE]
package main

import (
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"nodetrust/internal/version"
	"nodetrust/pkg/agent"
	"nodetrust/pkg/protocol"
)

const defaultIMALog = "/sys/kernel/security/ima/binary_runtime_measurements"

// defaultIMACount is the number of IMA measurements, polled for hints.
const defaultIMACount = "/sys/kernel/security/ima/runtime_measurements_count"

// defaultEventLog is the firmware's TCG event log. NODETRUST_EVENTLOG=none
// turns it off (swtpm has no firmware, so no log).
const defaultEventLog = "/sys/kernel/security/tpm0/binary_bios_measurements"

func eventLogPath(v string) string {
	if v == "none" {
		return ""
	}
	return v
}

// envOr lets tests point the agent at a software TPM and a test log
// (NODETRUST_TPM_DEVICE=tcp:127.0.0.1:2321, NODETRUST_IMA_LOG=...).
func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	if len(os.Args) > 1 {
		var err error
		switch os.Args[1] {
		case "enroll-request":
			err = enrollRequest(os.Args[2:])
		case "activate":
			err = activate(os.Args[2:])
		case "quote":
			err = quote(os.Args[2:])
		case "serve":
			err = serve(os.Args[2:])
		default:
			goto flags
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "nodetrust-agent:", err)
			os.Exit(1)
		}
		return
	}
flags:
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("agent"))
		return
	}
	fmt.Fprintln(os.Stderr, "usage: agent enroll-request | activate -challenge B64 | quote -nonce HEX -out FILE")
	os.Exit(2)
}

func openTPM(fs *flag.FlagSet, args []string) (*agent.TPM, error) {
	dev := fs.String("device", envOr("NODETRUST_TPM_DEVICE", agent.DefaultDevice), "TPM device")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return agent.Open(*dev)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(v)
}

func enrollRequest(args []string) error {
	fs := flag.NewFlagSet("enroll-request", flag.ContinueOnError)
	t, err := openTPM(fs, args)
	if err != nil {
		return err
	}
	defer t.Close()
	iid, _ := os.ReadFile("/var/lib/cloud/data/instance-id")
	return printJSON(protocol.EnrollRequest{
		Version:    protocol.Version,
		InstanceID: string(trimNL(iid)),
		EKPublic:   t.EK.Public,
		AKPublic:   t.AK.Public,
	})
}

func activate(args []string) error {
	fs := flag.NewFlagSet("activate", flag.ContinueOnError)
	chB64 := fs.String("challenge", "", "base64 of the Challenge JSON")
	t, err := openTPM(fs, args)
	if err != nil {
		return err
	}
	defer t.Close()
	raw, err := base64.StdEncoding.DecodeString(*chB64)
	if err != nil {
		return fmt.Errorf("challenge is not base64: %w", err)
	}
	var ch protocol.Challenge
	if err := json.Unmarshal(raw, &ch); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	if ch.Version != protocol.Version {
		return fmt.Errorf("challenge version %q, want %q", ch.Version, protocol.Version)
	}
	secret, err := t.ActivateCredential(ch.IDObject, ch.EncryptedSecret)
	if err != nil {
		return err
	}
	return printJSON(protocol.ChallengeResponse{Version: protocol.Version, Secret: secret})
}

func quote(args []string) error {
	fs := flag.NewFlagSet("quote", flag.ContinueOnError)
	nonceHex := fs.String("nonce", "", "verifier nonce (hex)")
	out := fs.String("out", "", "output file (gzipped JSON)")
	logPath := fs.String("ima-log", envOr("NODETRUST_IMA_LOG", defaultIMALog), "IMA binary log")
	evPath := fs.String("event-log", envOr("NODETRUST_EVENTLOG", defaultEventLog), `boot event log ("none" for none)`)
	t, err := openTPM(fs, args)
	if err != nil {
		return err
	}
	defer t.Close()
	if *out == "" {
		return errors.New("-out is required")
	}
	nonce, err := hex.DecodeString(*nonceHex)
	if err != nil {
		return fmt.Errorf("nonce is not hex: %w", err)
	}
	q, err := t.Quote(nonce)
	if err != nil {
		return err
	}
	// Read the log after the quote: the kernel adds an entry to the log
	// before it extends PCR 10, so this log holds everything the quote covers.
	log, err := os.ReadFile(*logPath)
	if err != nil {
		return fmt.Errorf("read IMA log: %w", err)
	}
	resp := protocol.QuoteResponse{
		Version:   protocol.Version,
		Attest:    q.Attest,
		Signature: q.Signature,
		PCRs:      map[string][]byte{},
		IMALog:    log,
	}
	if p := eventLogPath(*evPath); p != "" {
		if resp.EventLog, err = os.ReadFile(p); err != nil {
			return fmt.Errorf("read boot event log: %w", err)
		}
	}
	for i, v := range q.PCRs {
		resp.PCRs[strconv.Itoa(i)] = v
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	zw := gzip.NewWriter(f)
	if err := json.NewEncoder(zw).Encode(resp); err != nil {
		f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("quote written to %s (%d IMA log bytes)\n", *out, len(log))
	return nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
