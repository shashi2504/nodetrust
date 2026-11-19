package attest

// Cross-checks against go-tpm, an independent implementation of the same TPM
// structures and credential protection. pkg/attest itself does not import
// go-tpm; only this test does. The check against a real TPM (simulator and
// NitroTPM) is in pkg/agent.

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm/tpm2"

	"nodetrust/pkg/agent"
)

func TestKDFsMatchGoTPM(t *testing.T) {
	for _, bits := range []int{128, 256, 384, 512, 1000} {
		key, u, v := make([]byte, 32), make([]byte, 34), make([]byte, 17)
		rand.Read(key)
		rand.Read(u)
		rand.Read(v)
		if !bytes.Equal(kdfa(crypto.SHA256, key, "STORAGE", u, v, bits), tpm2.KDFa(crypto.SHA256, key, "STORAGE", u, v, bits)) {
			t.Errorf("KDFa differs from go-tpm at %d bits", bits)
		}
		if !bytes.Equal(kdfe(crypto.SHA256, key, "IDENTITY", u, v, bits), tpm2.KDFe(crypto.SHA256, key, "IDENTITY", u, v, bits)) {
			t.Errorf("KDFe differs from go-tpm at %d bits", bits)
		}
	}
}

func rsaEKPublic(k *rsa.PublicKey) tpm2.TPMTPublic {
	p := tpm2.RSAEKTemplate
	p.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgRSA, &tpm2.TPM2BPublicKeyRSA{Buffer: k.N.Bytes()})
	return p
}

func eccPublic(tmpl tpm2.TPMTPublic, k *ecdsa.PublicKey) tpm2.TPMTPublic {
	tmpl.Unique = tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
		X: tpm2.TPM2BECCParameter{Buffer: k.X.FillBytes(make([]byte, 32))},
		Y: tpm2.TPM2BECCParameter{Buffer: k.Y.FillBytes(make([]byte, 32))},
	})
	return tmpl
}

func TestParsePublicMatchesGoTPM(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	rsaEK := tpm2.Marshal(rsaEKPublic(&rk.PublicKey))
	p := mustParse(t, rsaEK)
	if !p.SameKey(&rk.PublicKey) || p.SymBits != 128 || p.SymMode != algCFB || !bytes.Equal(p.AuthPolicy, ekPolicy) {
		t.Fatalf("RSA EK template parsed wrong: %+v", p)
	}
	if mine := MarshalRSAPublic(algSHA256, p.Attributes, ekPolicy, algAES, 128, algCFB, algNull, 0, &rk.PublicKey); !bytes.Equal(mine, rsaEK) {
		t.Fatal("MarshalRSAPublic differs from go-tpm's marshalling of the RSA EK template")
	}
	if err := p.CheckEK(&rk.PublicKey); err != nil {
		t.Fatalf("go-tpm's RSA EK template fails CheckEK: %v", err)
	}
	if p.Attributes != ekAttrs {
		t.Fatalf("EK attributes 0x%08x, test constant 0x%08x", p.Attributes, ekAttrs)
	}

	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if p := mustParse(t, tpm2.Marshal(eccPublic(tpm2.ECCEKTemplate, &ek.PublicKey))); !p.SameKey(&ek.PublicKey) {
		t.Fatal("ECC EK template parsed wrong")
	}

	// The agent's AK template is a valid AK, and its name matches go-tpm's.
	ak, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	akPub := eccPublic(agent.AKTemplate, &ak.PublicKey)
	ap := mustParse(t, tpm2.Marshal(akPub))
	if err := ap.CheckAK(); err != nil {
		t.Fatalf("agent.AKTemplate is not accepted as an AK: %v", err)
	}
	name, _ := ap.Name()
	want, err := tpm2.ObjectName(&akPub)
	if err != nil || !bytes.Equal(name, want.Buffer) {
		t.Fatalf("AK name %x, go-tpm says %x (%v)", name, want.Buffer, err)
	}
}

// go-tpm's CreateCredential output must open with our inverse, so both
// implementations build the credential the same way.
func TestCredentialMatchesGoTPM(t *testing.T) {
	akName := append([]byte{0, 0x0b}, make([]byte, 32)...)
	rand.Read(akName[2:])
	secret := []byte("credential from go-tpm")

	t.Run("RSA EK", func(t *testing.T) {
		rk, _ := rsa.GenerateKey(rand.Reader, 2048)
		pub := rsaEKPublic(&rk.PublicKey)
		kem, err := tpm2.ImportEncapsulationKey(&pub)
		if err != nil {
			t.Fatal(err)
		}
		id, enc, err := tpm2.CreateCredential(rand.Reader, kem, akName, secret)
		if err != nil {
			t.Fatal(err)
		}
		seed, err := rsa.DecryptOAEP(sha256.New(), nil, rk, enc, []byte("IDENTITY\x00"))
		if err != nil {
			t.Fatal(err)
		}
		ek := mustParse(t, tpm2.Marshal(pub))
		got, err := decryptCredential(ek, seed, akName, &Credential{IDObject: id, EncryptedSecret: enc})
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("%v %q", err, got)
		}
	})

	t.Run("ECC EK", func(t *testing.T) {
		ekPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub := eccPublic(tpm2.ECCEKTemplate, &ekPriv.PublicKey)
		kem, err := tpm2.ImportEncapsulationKey(&pub)
		if err != nil {
			t.Fatal(err)
		}
		id, enc, err := tpm2.CreateCredential(rand.Reader, kem, akName, secret)
		if err != nil {
			t.Fatal(err)
		}
		r := &reader{b: enc}
		ex, ey := r.tpm2b(), r.tpm2b()
		eph, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, ex...), ey...))
		if err != nil {
			t.Fatal(err)
		}
		priv, _ := ekPriv.ECDH()
		z, _ := priv.ECDH(eph)
		seed := kdfe(crypto.SHA256, z, "IDENTITY", ex, ekPriv.X.FillBytes(make([]byte, 32)), 256)
		ek := mustParse(t, tpm2.Marshal(pub))
		got, err := decryptCredential(ek, seed, akName, &Credential{IDObject: id, EncryptedSecret: enc})
		if err != nil || !bytes.Equal(got, secret) {
			t.Fatalf("%v %q", err, got)
		}
	})
}

// A quote marshalled by go-tpm verifies with VerifyQuote.
func TestQuoteMatchesGoTPM(t *testing.T) {
	ak, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	akPub := mustParse(t, tpm2.Marshal(eccPublic(agent.AKTemplate, &ak.PublicKey)))
	pcrs := pcrValues(11)
	d := sha256.New()
	for i := 0; i < 11; i++ {
		d.Write(pcrs[i])
	}
	nonce := []byte("nonce-from-the-verifier")
	attest := tpm2.Marshal(tpm2.TPMSAttest{
		Magic:           tpm2.TPMGeneratedValue,
		Type:            tpm2.TPMSTAttestQuote,
		QualifiedSigner: tpm2.TPM2BName{Buffer: []byte("qn")},
		ExtraData:       tpm2.TPM2BData{Buffer: nonce},
		ClockInfo:       tpm2.TPMSClockInfo{Clock: 99, ResetCount: 3, RestartCount: 0, Safe: true},
		FirmwareVersion: 42,
		Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote, &tpm2.TPMSQuoteInfo{
			PCRSelect: tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10),
			}}},
			PCRDigest: tpm2.TPM2BDigest{Buffer: d.Sum(nil)},
		}),
	})
	h := sha256.Sum256(attest)
	r, s, _ := ecdsa.Sign(rand.Reader, ak, h[:])
	sig := tpm2.Marshal(tpm2.TPMTSignature{
		SigAlg: tpm2.TPMAlgECDSA,
		Signature: tpm2.NewTPMUSignature(tpm2.TPMAlgECDSA, &tpm2.TPMSSignatureECC{
			Hash:       tpm2.TPMAlgSHA256,
			SignatureR: tpm2.TPM2BECCParameter{Buffer: r.Bytes()},
			SignatureS: tpm2.TPM2BECCParameter{Buffer: s.Bytes()},
		}),
	})
	q, err := VerifyQuote(akPub, attest, sig, nonce, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	if q.ResetCount != 3 || q.FirmwareVersion != 42 || !q.Safe {
		t.Fatalf("parsed %+v", q)
	}
}
