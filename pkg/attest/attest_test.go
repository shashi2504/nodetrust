package attest

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

const ekAttrs = AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy | AttrRestricted | AttrDecrypt
const akAttrs = AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrSign

// The TCG EK policy: PolicySecret(TPM_RH_ENDORSEMENT).
var ekPolicy = []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
	0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa}

func mustParse(t *testing.T, raw []byte) *Public {
	t.Helper()
	p, err := ParsePublic(raw)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newAK(t *testing.T) (*ecdsa.PrivateKey, *Public) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return k, mustParse(t, MarshalECCPublic(algSHA256, akAttrs, nil, algNull, 0, 0, algECDSA, algSHA256, &k.PublicKey))
}

func TestParsePublicRoundTrip(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek := mustParse(t, MarshalRSAPublic(algSHA256, ekAttrs, ekPolicy, algAES, 128, algCFB, algNull, 0, &rk.PublicKey))
	if !ek.SameKey(&rk.PublicKey) || ek.SymBits != 128 || !bytes.Equal(ek.AuthPolicy, ekPolicy) {
		t.Fatalf("RSA EK parsed wrong: %+v", ek)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if ek.SameKey(&other.PublicKey) {
		t.Fatal("SameKey accepted a different key")
	}
	name, _ := ek.Name()
	h := sha256.Sum256(ek.Raw)
	if !bytes.Equal(name, append([]byte{0, 0x0b}, h[:]...)) {
		t.Fatal("name is not nameAlg || SHA256(TPMT_PUBLIC)")
	}
	_, ak := newAK(t)
	if err := ak.CheckAK(); err != nil {
		t.Fatal(err)
	}
	if ek.CheckAK() == nil {
		t.Fatal("an EK passed as an AK")
	}
}

func TestParsePublicRejects(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	good := MarshalECCPublic(algSHA256, akAttrs, nil, algNull, 0, 0, algECDSA, algSHA256, &k.PublicKey)
	cases := map[string][]byte{
		"truncated": good[:len(good)-3],
		"trailing":  append(append([]byte{}, good...), 0),
		"sha1 name": MarshalECCPublic(algSHA1, akAttrs, nil, algNull, 0, 0, algECDSA, algSHA256, &k.PublicKey),
	}
	offCurve := append([]byte{}, good...)
	offCurve[len(offCurve)-1] ^= 1 // last byte of Y
	cases["point off curve"] = offCurve
	for name, raw := range cases {
		if _, err := ParsePublic(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Parses, but is not an AK.
	for name, attrs := range map[string]uint32{
		"not restricted": akAttrs &^ AttrRestricted,
		"not fixedTPM":   akAttrs &^ AttrFixedTPM,
		"also decrypt":   akAttrs | AttrDecrypt,
	} {
		p := mustParse(t, MarshalECCPublic(algSHA256, attrs, nil, algNull, 0, 0, algECDSA, algSHA256, &k.PublicKey))
		if p.CheckAK() == nil {
			t.Errorf("%s: passed CheckAK", name)
		}
	}
}

func TestMakeCredentialRSA(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek := mustParse(t, MarshalRSAPublic(algSHA256, ekAttrs, ekPolicy, algAES, 128, algCFB, algNull, 0, &rk.PublicKey))
	_, ak := newAK(t)
	akName, _ := ak.Name()
	secret := []byte("0123456789abcdef0123456789abcdef")
	c, err := MakeCredential(nil, ek, akName, secret)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := rsa.DecryptOAEP(sha256.New(), nil, rk, c.EncryptedSecret, []byte("IDENTITY\x00"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptCredential(ek, seed, akName, c)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: %v %q", err, got)
	}
	// Bound to the AK name: another object cannot activate it.
	_, other := newAK(t)
	otherName, _ := other.Name()
	if _, err := decryptCredential(ek, seed, otherName, c); err == nil {
		t.Fatal("credential activated for a different AK")
	}
	// The wrong label (as a TPM would use for a different purpose) fails.
	if _, err := rsa.DecryptOAEP(sha256.New(), nil, rk, c.EncryptedSecret, []byte("IDENTITY")); err == nil {
		t.Fatal("OAEP label without the zero byte accepted")
	}
}

func TestMakeCredentialECC(t *testing.T) {
	ekPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ek := mustParse(t, MarshalECCPublic(algSHA256, ekAttrs, ekPolicy, algAES, 128, algCFB, algNull, 0, &ekPriv.PublicKey))
	_, ak := newAK(t)
	akName, _ := ak.Name()
	secret := []byte("ecc secret")
	c, err := MakeCredential(nil, ek, akName, secret)
	if err != nil {
		t.Fatal(err)
	}
	// TPM side: Z = ECDH(EK private, ephemeral point), seed = KDFe(...).
	r := &reader{b: c.EncryptedSecret}
	ex, ey := r.tpm2b(), r.tpm2b()
	eph, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, ex...), ey...))
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := ekPriv.ECDH()
	z, _ := priv.ECDH(eph)
	seed := kdfe(crypto.SHA256, z, "IDENTITY", ex, ekPriv.X.FillBytes(make([]byte, 32)), 256)
	got, err := decryptCredential(ek, seed, akName, c)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("round trip: %v %q", err, got)
	}
}

func TestMakeCredentialRejects(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	notStorage := mustParse(t, MarshalRSAPublic(algSHA256, ekAttrs&^AttrDecrypt|AttrSign, nil, algNull, 0, 0, algRSASSA, algSHA256, &rk.PublicKey))
	if _, err := MakeCredential(nil, notStorage, []byte("n"), []byte("s")); err == nil {
		t.Fatal("made a credential for a signing key")
	}
	ek := mustParse(t, MarshalRSAPublic(algSHA256, ekAttrs, ekPolicy, algAES, 128, algCFB, algNull, 0, &rk.PublicKey))
	if _, err := MakeCredential(nil, ek, []byte("n"), make([]byte, 33)); err == nil {
		t.Fatal("accepted a secret longer than the digest")
	}
}

// --- quotes ---------------------------------------------------------------------

func pcrValues(n int) map[int][]byte {
	m := map[int][]byte{}
	for i := 0; i < n; i++ {
		v := sha256.Sum256([]byte{byte(i)})
		m[i] = v[:]
	}
	return m
}

func buildAttest(nonce []byte, pcrs map[int][]byte, magic uint32, typ uint16) []byte {
	b := binary.BigEndian.AppendUint32(nil, magic)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = appendTPM2B(b, []byte("qualified-signer"))
	b = appendTPM2B(b, nonce)
	b = binary.BigEndian.AppendUint64(b, 123456)
	b = binary.BigEndian.AppendUint32(b, 7) // resetCount
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, 1)
	b = binary.BigEndian.AppendUint64(b, 0x2000)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint16(b, algSHA256)
	bitmap := make([]byte, 3)
	d := sha256.New()
	for i := 0; i < 24; i++ {
		if v, ok := pcrs[i]; ok {
			bitmap[i/8] |= 1 << (i % 8)
			d.Write(v)
		}
	}
	b = append(b, 3)
	b = append(b, bitmap...)
	return appendTPM2B(b, d.Sum(nil))
}

func signECDSA(k *ecdsa.PrivateKey, data []byte) []byte {
	h := sha256.Sum256(data)
	r, s, _ := ecdsa.Sign(rand.Reader, k, h[:])
	b := binary.BigEndian.AppendUint16(nil, algECDSA)
	b = binary.BigEndian.AppendUint16(b, algSHA256)
	b = appendTPM2B(b, r.Bytes())
	return appendTPM2B(b, s.Bytes())
}

func TestVerifyQuote(t *testing.T) {
	k, ak := newAK(t)
	nonce := []byte("fresh-nonce-0123456789")
	pcrs := pcrValues(11)
	attest := buildAttest(nonce, pcrs, attestMagic, stAttestQuot)
	sig := signECDSA(k, attest)
	q, err := VerifyQuote(ak, attest, sig, nonce, pcrs)
	if err != nil {
		t.Fatal(err)
	}
	if q.ResetCount != 7 || !q.Safe || len(q.Selection[0].PCRs) != 11 {
		t.Fatalf("parsed %+v", q)
	}

	_, other := newAK(t)
	badPCR := pcrValues(11)
	badPCR[10] = make([]byte, 32)
	fewer := pcrValues(10)
	tampered := append([]byte{}, attest...)
	tampered[len(tampered)-1] ^= 1
	notGenerated := buildAttest(nonce, pcrs, 0x12345678, stAttestQuot)
	for name, tc := range map[string]struct {
		ak     *Public
		attest []byte
		sig    []byte
		nonce  []byte
		pcrs   map[int][]byte
		want   string
	}{
		"wrong nonce":   {ak, attest, sig, []byte("old-nonce"), pcrs, "nonce"},
		"empty nonce":   {ak, buildAttest(nil, pcrs, attestMagic, stAttestQuot), signECDSA(k, buildAttest(nil, pcrs, attestMagic, stAttestQuot)), nil, pcrs, "nonce"},
		"wrong PCR":     {ak, attest, sig, nonce, badPCR, "PCR values"},
		"missing PCR":   {ak, attest, sig, nonce, fewer, "covers PCRs"},
		"other AK":      {other, attest, sig, nonce, pcrs, "does not verify"},
		"tampered":      {ak, tampered, sig, nonce, pcrs, "does not verify"},
		"not generated": {ak, notGenerated, signECDSA(k, notGenerated), nonce, pcrs, "TPM_GENERATED"},
		"not a quote":   {ak, buildAttest(nonce, pcrs, attestMagic, 0x8017), signECDSA(k, buildAttest(nonce, pcrs, attestMagic, 0x8017)), nonce, pcrs, "not a quote"},
		"garbage sig":   {ak, attest, []byte{0, 0x18}, nonce, pcrs, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyQuote(tc.ak, tc.attest, tc.sig, tc.nonce, tc.pcrs)
			if err == nil {
				t.Fatal("accepted")
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestCheckEK(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek := mustParse(t, MarshalRSAPublic(algSHA256, ekAttrs, ekPolicy, algAES, 128, algCFB, algNull, 0, &rk.PublicKey))
	if err := ek.CheckEK(&rk.PublicKey); err != nil {
		t.Fatal(err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if ek.CheckEK(&other.PublicKey) == nil {
		t.Fatal("EK accepted against another instance's key")
	}
	noPolicy := mustParse(t, MarshalRSAPublic(algSHA256, ekAttrs, nil, algAES, 128, algCFB, algNull, 0, &rk.PublicKey))
	if noPolicy.CheckEK(&rk.PublicKey) == nil {
		t.Fatal("EK without the TCG policy accepted")
	}
	userAuth := mustParse(t, MarshalRSAPublic(algSHA256, ekAttrs|AttrUserWithAuth, ekPolicy, algAES, 128, algCFB, algNull, 0, &rk.PublicKey))
	if userAuth.CheckEK(&rk.PublicKey) == nil {
		t.Fatal("EK with userWithAuth accepted")
	}
}

func TestParseCloudEK(t *testing.T) {
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	spki, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	for _, der := range [][]byte{spki, x509.MarshalPKCS1PublicKey(&rk.PublicKey)} {
		k, err := ParseCloudEK(base64.StdEncoding.EncodeToString(der) + "\n")
		if err != nil || !rk.PublicKey.Equal(k) {
			t.Fatalf("%v", err)
		}
	}
	if _, err := ParseCloudEK("bm90IGEga2V5"); err == nil {
		t.Fatal("parsed garbage")
	}
}
