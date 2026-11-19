//go:build simulator

// Package tpmsim_test checks that the in-memory TPM 2.0 simulator works in CI.
// The simulator is used ONLY in unit tests. Development runs, integration
// tests and the evaluation all use NitroTPM on EC2.
//
// Run with: go test -tags simulator ./internal/tpmsim/...
// The simulator is C code built through cgo, so a C compiler is required.
package tpmsim_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"
)

// debugPCR is PCR 16, the debug PCR, which is free for tests.
const debugPCR = 16

func readPCR(t *testing.T, tpm transport.TPM, index uint) []byte {
	t.Helper()
	resp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(index),
			}},
		},
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("PCRRead(%d): %v", index, err)
	}
	if n := len(resp.PCRValues.Digests); n != 1 {
		t.Fatalf("PCRRead(%d): got %d digests, want 1", index, n)
	}
	return resp.PCRValues.Digests[0].Buffer
}

// TestPCRExtendMatchesSoftwareReplay extends a PCR on the simulator and checks
// that the result equals new = SHA256(old || digest). The verifier relies on
// exactly this rule when it replays the IMA log against PCR 10.
func TestPCRExtendMatchesSoftwareReplay(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open simulator: %v", err)
	}
	defer tpm.Close()

	before := readPCR(t, tpm, debugPCR)

	measurement := sha256.Sum256([]byte("nodetrust phase 0"))
	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(debugPCR),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: measurement[:]}},
		},
	}.Execute(tpm)
	if err != nil {
		t.Fatalf("PCRExtend: %v", err)
	}

	after := readPCR(t, tpm, debugPCR)

	h := sha256.New()
	h.Write(before)
	h.Write(measurement[:])
	want := h.Sum(nil)

	if !bytes.Equal(after, want) {
		t.Fatalf("PCR %d after extend = %x, software replay = %x", debugPCR, after, want)
	}
}
