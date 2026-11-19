//go:build simulator

// End-to-end test of step 3.2 on a TPM simulator: agent and verifier code
// exchange the real protocol messages, and the simulator's PCR 10 is
// extended with the entries of an IMA log so the log replay is checked too.
package verifier

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"nodetrust/pkg/agent"
	"nodetrust/pkg/attest"
	"nodetrust/pkg/ima"
	"nodetrust/pkg/protocol"
)

func TestEnrollAndQuoteOnSimulator(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	a, err := agent.New(sim)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	// The "cloud" vouches for the simulator's EK, as EC2 does for NitroTPM.
	ekPub, _ := attest.ParsePublic(a.EK.Public)
	cloudEK := ekPub.Key

	req := &protocol.EnrollRequest{Version: protocol.Version, EKPublic: a.EK.Public, AKPublic: a.AK.Public}
	ch, pending, err := NewChallenge("i-sim", cloudEK, req)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := a.ActivateCredential(ch.IDObject, ch.EncryptedSecret)
	if err != nil {
		t.Fatal(err)
	}
	enr, err := Finish(pending, &protocol.ChallengeResponse{Version: protocol.Version, Secret: secret}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// Another instance's EK must not get a challenge for this TPM's AK.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, _, err := NewChallenge("i-sim", &other.PublicKey, req); err == nil {
		t.Fatal("challenge made although the EK is not the cloud's")
	}
	// A wrong secret fails.
	if _, err := Finish(pending, &protocol.ChallengeResponse{Version: protocol.Version, Secret: make([]byte, 32)}, time.Now()); err == nil {
		t.Fatal("wrong secret accepted")
	}

	// Build an IMA log and extend PCR 10 with it, like the kernel does.
	log := imaLog([][2]string{{"boot_aggregate", "a"}, {"/usr/bin/kubelet", "k"}, {"/etc/hostname", "h"}})
	entries, _ := ima.ParseLog(log)
	for _, e := range entries {
		d := sha256.Sum256(e.TemplateData)
		if _, err := (tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(10), Auth: tpm2.PasswordAuth(nil)},
			Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
		}).Execute(sim); err != nil {
			t.Fatal(err)
		}
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)
	q, err := a.Quote(nonce)
	if err != nil {
		t.Fatal(err)
	}
	resp := &protocol.QuoteResponse{Version: protocol.Version, Attest: q.Attest, Signature: q.Signature,
		PCRs: map[string][]byte{}, IMALog: append(log, imaLog([][2]string{{"/late", "l"}})...)}
	for i, v := range q.PCRs {
		resp.PCRs[strconv.Itoa(i)] = v
	}
	res, err := CheckQuote(enr, nonce, resp, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.IMA.Attested != 3 || res.IMA.After != 1 {
		t.Fatalf("replay %+v, want 3 attested and 1 after", res.IMA)
	}
	// The same quote with another nonce, or with an edited log, fails.
	if _, err := CheckQuote(enr, []byte("replayed"), resp, nil); err == nil {
		t.Fatal("replayed quote accepted")
	}
	// A boot event log must replay to the quoted PCRs 0-9. The simulator has
	// no firmware, so they are zero: a log with only its header replays to
	// them, and the NitroTPM log does not.
	nitro, err := os.ReadFile("../eventlog/testdata/nitro-ami-07deef95.bin")
	if err != nil {
		t.Fatal(err)
	}
	hdrLen := 32 + int(binary.LittleEndian.Uint32(nitro[28:32])) // TCG_PCR_EVENT with a SHA-1 slot
	resp.EventLog = nitro[:hdrLen]
	if res, err := CheckQuote(enr, nonce, resp, nil); err != nil || res.BootLog == nil || len(res.BootLog.Events) != 0 {
		t.Fatalf("header-only event log: %v", err)
	}
	resp.EventLog = nitro
	if _, err := CheckQuote(enr, nonce, resp, nil); err == nil || !strings.Contains(err.Error(), "replay of PCR 0") {
		t.Fatalf("event log of another machine: %v", err)
	}
	resp.EventLog = nil

	resp.IMALog = imaLog([][2]string{{"boot_aggregate", "a"}, {"/usr/bin/kubelet", "EVIL"}, {"/etc/hostname", "h"}})
	if _, err := CheckQuote(enr, nonce, resp, nil); err == nil {
		t.Fatal("edited IMA log accepted")
	}
}
