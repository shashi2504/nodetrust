package manifest

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
)

type fixture struct {
	key       *ecdsa.PrivateKey
	gz        []byte
	raw       []byte
	statement []byte
	sig       []byte
}

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sign(t *testing.T, k *ecdsa.PrivateKey, msg []byte) []byte {
	t.Helper()
	d := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return []byte(base64.StdEncoding.EncodeToString(der) + "\n")
}

func newFixture(t *testing.T, edit func(*Statement)) fixture {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	entries := strings.Repeat("0", 64)
	raw := []byte(`{"schema":"` + ManifestSchema + `","entries_sha256":"` + entries +
		`","source":{"ami_id":"ami-0123456789abcdef0","snapshot_id":"snap-0123456789abcdef0","region":"ap-south-1"},"entries":[]}`)
	gz := gzipBytes(t, raw)
	s := Statement{
		Schema:           StatementSchema,
		AMIID:            "ami-0123456789abcdef0",
		SnapshotID:       "snap-0123456789abcdef0",
		Region:           "ap-south-1",
		ManifestURI:      "s3://bucket/manifests/ami-0123456789abcdef0/manifest.json.gz",
		ManifestSHA256:   sum(raw),
		ManifestGzSHA256: sum(gz),
		EntriesSHA256:    entries,
		BuildInfo:        map[string]string{"kubelet": "1.35.10-1.1"},
		KeyID:            "arn:aws:kms:ap-south-1:111122223333:key/test",
		SignedAt:         "2026-11-15T00:00:00Z",
	}
	if edit != nil {
		edit(&s)
	}
	st, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{key: k, gz: gz, raw: raw, statement: st, sig: sign(t, k, st)}
}

func TestVerifyGood(t *testing.T) {
	f := newFixture(t, nil)
	s, err := VerifyStatement(f.statement, f.sig, &f.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := s.CheckManifestGz(f.gz)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, f.raw) {
		t.Fatal("returned manifest differs")
	}
}

func TestTamperedStatement(t *testing.T) {
	f := newFixture(t, nil)
	bad := bytes.Replace(f.statement, []byte("ami-0123456789abcdef0"), []byte("ami-0123456789abcdef1"), 1)
	if _, err := VerifyStatement(bad, f.sig, &f.key.PublicKey); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestWrongKey(t *testing.T) {
	f := newFixture(t, nil)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := VerifyStatement(f.statement, f.sig, &other.PublicKey); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("got %v, want ErrBadSignature", err)
	}
}

func TestGarbageSignature(t *testing.T) {
	f := newFixture(t, nil)
	if _, err := VerifyStatement(f.statement, []byte("!!!"), &f.key.PublicKey); err == nil {
		t.Fatal("accepted non-base64 signature")
	}
}

func TestSignedButInvalidFields(t *testing.T) {
	for name, edit := range map[string]func(*Statement){
		"schema": func(s *Statement) { s.Schema = "other" },
		"ami":    func(s *Statement) { s.AMIID = "ami-XYZ" },
		"hash":   func(s *Statement) { s.ManifestSHA256 = "abc" },
		"key":    func(s *Statement) { s.KeyID = "" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, edit)
			if _, err := VerifyStatement(f.statement, f.sig, &f.key.PublicKey); err == nil {
				t.Fatal("accepted invalid statement")
			}
		})
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	f := newFixture(t, nil)
	st := append(bytes.TrimSuffix(f.statement, []byte("}")), []byte(`,"extra":1}`)...)
	if _, err := VerifyStatement(st, sign(t, f.key, st), &f.key.PublicKey); err == nil {
		t.Fatal("accepted unknown field")
	}
}

func TestManifestMismatches(t *testing.T) {
	f := newFixture(t, nil)
	s, err := VerifyStatement(f.statement, f.sig, &f.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// A different manifest, even a valid one, must not pass.
	other := bytes.Replace(f.raw, []byte(`"entries":[]`), []byte(`"entries":[{"path":"/x"}]`), 1)
	if _, err := s.CheckManifestGz(gzipBytes(t, other)); err == nil {
		t.Fatal("accepted a different manifest")
	}
	// Same JSON, different gzip framing: the .gz hash is signed too.
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.NoCompression)
	_, _ = w.Write(f.raw)
	_ = w.Close()
	if _, err := s.CheckManifestGz(buf.Bytes()); err == nil {
		t.Fatal("accepted re-gzipped manifest")
	}
}

func TestManifestForAnotherAMI(t *testing.T) {
	// The statement is signed and the hashes match, but the manifest inside
	// names a different AMI: the binding check must catch it.
	f := newFixture(t, nil)
	raw := bytes.Replace(f.raw, []byte("ami-0123456789abcdef0"), []byte("ami-0fedcba9876543210"), 1)
	gz := gzipBytes(t, raw)
	f2 := newFixture(t, func(s *Statement) { s.ManifestSHA256, s.ManifestGzSHA256 = sum(raw), sum(gz) })
	s, err := VerifyStatement(f2.statement, f2.sig, &f2.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CheckManifestGz(gz); err == nil || !strings.Contains(err.Error(), "built from") {
		t.Fatalf("got %v, want AMI binding error", err)
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	got, err := ParsePublicKeyPEM(p)
	if err != nil || !got.Equal(&k.PublicKey) {
		t.Fatalf("round trip failed: %v", err)
	}
	k384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der, _ = x509.MarshalPKIXPublicKey(&k384.PublicKey)
	if _, err := ParsePublicKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})); err == nil {
		t.Fatal("accepted a P-384 key")
	}
	if _, err := ParsePublicKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("accepted garbage")
	}
}
