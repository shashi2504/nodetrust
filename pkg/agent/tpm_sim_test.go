//go:build simulator

// Simulator tests for the agent's TPM layer against the verifier code in
// pkg/attest. These are the conformance check for attest.MakeCredential and
// attest.VerifyQuote: a real TPM implementation (the reference simulator)
// must accept our credential and produce quotes our verifier accepts.
//
// Run with: make test-sim (needs cgo and a C compiler).
package agent

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"nodetrust/pkg/attest"
)

func openSim(t *testing.T) (transport.TPMCloser, *TPM) {
	t.Helper()
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("open simulator: %v", err)
	}
	a, err := New(sim)
	if err != nil {
		sim.Close()
		t.Fatalf("New: %v", err)
	}
	return sim, a
}

func parseKeys(t *testing.T, a *TPM) (ek, ak *attest.Public) {
	t.Helper()
	ek, err := attest.ParsePublic(a.EK.Public)
	if err != nil {
		t.Fatalf("parse EK: %v", err)
	}
	ak, err = attest.ParsePublic(a.AK.Public)
	if err != nil {
		t.Fatalf("parse AK: %v", err)
	}
	if err := ak.CheckAK(); err != nil {
		t.Fatalf("AK from the TPM fails CheckAK: %v", err)
	}
	name, _ := ak.Name()
	if !bytes.Equal(name, a.AK.Name.Buffer) {
		t.Fatalf("AK name: ours %x, TPM %x", name, a.AK.Name.Buffer)
	}
	return ek, ak
}

func TestKeysAreStable(t *testing.T) {
	sim, a := openSim(t)
	defer sim.Close()
	ek1, ak1 := append([]byte(nil), a.EK.Public...), append([]byte(nil), a.AK.Public...)
	parseKeys(t, a)
	a.Close()

	// Same TPM, same seeds: the same keys again, so nothing is stored on disk.
	b, err := New(sim)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !bytes.Equal(ek1, b.EK.Public) || !bytes.Equal(ak1, b.AK.Public) {
		t.Fatal("EK or AK changed between two loads on the same TPM")
	}
}

// The core enrollment check: the TPM's ActivateCredential opens a credential
// made by attest.MakeCredential in software.
func TestActivateCredentialFromVerifier(t *testing.T) {
	sim, a := openSim(t)
	defer sim.Close()
	defer a.Close()
	ek, ak := parseKeys(t, a)
	akName, _ := ak.Name()

	secret := make([]byte, 32)
	rand.Read(secret)
	cred, err := attest.MakeCredential(nil, ek, akName, secret)
	if err != nil {
		t.Fatal(err)
	}
	got, err := a.ActivateCredential(cred.IDObject, cred.EncryptedSecret)
	if err != nil {
		t.Fatalf("TPM refused our credential: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("TPM returned %x, want %x", got, secret)
	}

	// A credential for some other object must not open with this AK.
	other := append([]byte{0, 0x0b}, make([]byte, 32)...)
	rand.Read(other[2:])
	cred2, _ := attest.MakeCredential(nil, ek, other, secret)
	if _, err := a.ActivateCredential(cred2.IDObject, cred2.EncryptedSecret); err == nil {
		t.Fatal("TPM opened a credential made for another object name")
	}

	// A tampered blob must fail the TPM's integrity check.
	bad := append([]byte(nil), cred.IDObject...)
	bad[len(bad)-1] ^= 1
	if _, err := a.ActivateCredential(bad, cred.EncryptedSecret); err == nil {
		t.Fatal("TPM opened a tampered credential")
	}
}

func TestQuoteVerifies(t *testing.T) {
	sim, a := openSim(t)
	defer sim.Close()
	defer a.Close()
	_, ak := parseKeys(t, a)

	nonce := make([]byte, 32)
	rand.Read(nonce)
	q, err := a.Quote(nonce)
	if err != nil {
		t.Fatal(err)
	}
	info, err := attest.VerifyQuote(ak, q.Attest, q.Signature, nonce, q.PCRs)
	if err != nil {
		t.Fatalf("our verifier rejects the TPM's quote: %v", err)
	}
	if len(info.Selection) != 1 || len(info.Selection[0].PCRs) != len(QuotePCRs) {
		t.Fatalf("quote covers %+v", info.Selection)
	}
	// Not obfuscated: a fresh simulator has been reset only a few times.
	if info.ResetCount > 1000 || info.RestartCount > 1000 {
		t.Fatalf("resetCount %d / restartCount %d look obfuscated; the AK must be in the endorsement hierarchy",
			info.ResetCount, info.RestartCount)
	}

	// Wrong nonce: rejected.
	if _, err := attest.VerifyQuote(ak, q.Attest, q.Signature, []byte("other"), q.PCRs); err == nil {
		t.Fatal("quote accepted with another nonce")
	}

	// Extend PCR 10 as IMA would: a new quote shows the new value, and the old
	// values no longer match it.
	old := q.PCRs
	if _, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(10), Auth: tpm2.PasswordAuth(nil)},
		Digests: tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{
			HashAlg: tpm2.TPMAlgSHA256, Digest: make([]byte, 32),
		}}},
	}).Execute(sim); err != nil {
		t.Fatal(err)
	}
	rand.Read(nonce)
	q2, err := a.Quote(nonce)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(q2.PCRs[10], old[10]) {
		t.Fatal("PCR 10 did not change after the extend")
	}
	if _, err := attest.VerifyQuote(ak, q2.Attest, q2.Signature, nonce, old); err == nil {
		t.Fatal("new quote accepted with the old PCR values")
	}
	if _, err := attest.VerifyQuote(ak, q2.Attest, q2.Signature, nonce, q2.PCRs); err != nil {
		t.Fatalf("new quote rejected: %v", err)
	}
}
