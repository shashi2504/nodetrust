package manifest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

// --- reference RFC 6962 tree (straight from the RFC's definitions) -----------

func leafHash(b []byte) []byte {
	h := sha256.Sum256(append([]byte{0}, b...))
	return h[:]
}

func splitPoint(n int) int { // largest power of two smaller than n
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func mth(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		h := sha256.Sum256(nil)
		return h[:]
	case 1:
		return leafHash(leaves[0])
	}
	k := splitPoint(len(leaves))
	return hashChildren(mth(leaves[:k]), mth(leaves[k:]))
}

func path(m int, leaves [][]byte) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := splitPoint(len(leaves))
	if m < k {
		return append(path(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(path(m-k, leaves[k:]), mth(leaves[:k]))
}

func TestInclusionAgainstReference(t *testing.T) {
	for n := 1; n <= 33; n++ {
		leaves := make([][]byte, n)
		for i := range leaves {
			leaves[i] = []byte(fmt.Sprintf("leaf-%d", i))
		}
		root := mth(leaves)
		for m := 0; m < n; m++ {
			p := path(m, leaves)
			if err := verifyInclusion(uint64(m), uint64(n), leafHash(leaves[m]), p, root); err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			if len(p) > 0 {
				bad := append([][]byte{}, p...)
				bad[0] = leafHash([]byte("x"))
				if verifyInclusion(uint64(m), uint64(n), leafHash(leaves[m]), bad, root) == nil {
					t.Fatalf("n=%d m=%d: accepted a bad proof", n, m)
				}
			}
			if m+1 < n && verifyInclusion(uint64(m+1), uint64(n), leafHash(leaves[m]), p, root) == nil && len(p) > 0 {
				t.Fatalf("n=%d m=%d: accepted the proof at the wrong index", n, m)
			}
		}
	}
}

// --- a fake Rekor -------------------------------------------------------------

type fakeRekor struct {
	key  *ecdsa.PrivateKey
	der  []byte
	name string
}

func newFakeRekor(t *testing.T) *fakeRekor {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return &fakeRekor{key: k, der: der, name: "rekor.example"}
}

func (r *fakeRekor) logID() string {
	h := sha256.Sum256(r.der)
	return hex.EncodeToString(h[:])
}

func (r *fakeRekor) sign(msg []byte) []byte {
	d := sha256.Sum256(msg)
	s, _ := ecdsa.SignASN1(rand.Reader, r.key, d[:])
	return s
}

func (r *fakeRekor) checkpoint(size int, root []byte) string {
	text := fmt.Sprintf("%s - 1193050959916656506\n%d\n%s\nTimestamp: 1763215400000000000\n",
		r.name, size, base64.StdEncoding.EncodeToString(root))
	h := sha256.Sum256(r.der)
	raw := make([]byte, 4)
	binary.BigEndian.PutUint32(raw, binary.BigEndian.Uint32(h[:4]))
	raw = append(raw, r.sign([]byte(text))...)
	return text + "\n— " + r.name + " " + base64.StdEncoding.EncodeToString(raw) + "\n"
}

// entry logs (statement, sig) as leaf `index` of a tree of `size` leaves and
// returns the response JSON Rekor would send.
func (r *fakeRekor) entry(t *testing.T, statement, sigB64, signerPEM []byte, index, size int) []byte {
	t.Helper()
	var hr hashedrekord
	hr.APIVersion, hr.Kind = "0.0.1", "hashedrekord"
	hr.Spec.Data.Hash.Algorithm = "sha256"
	hr.Spec.Data.Hash.Value = sum(statement)
	hr.Spec.Signature.Content = strings.TrimSpace(string(sigB64))
	hr.Spec.Signature.PublicKey.Content = base64.StdEncoding.EncodeToString(signerPEM)
	body, _ := json.Marshal(hr)

	leaves := make([][]byte, size)
	for i := range leaves {
		leaves[i] = []byte(fmt.Sprintf("other-%d", i))
	}
	leaves[index] = body
	root := mth(leaves)

	var e RekorEntry
	e.Body = base64.StdEncoding.EncodeToString(body)
	e.IntegratedTime = 1763215400
	e.LogID = r.logID()
	e.LogIndex = 900000000 + int64(index) // global index differs from the shard index
	payload, _ := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{e.Body, e.IntegratedTime, e.LogID, e.LogIndex})
	e.Verification.SignedEntryTimestamp = base64.StdEncoding.EncodeToString(r.sign(payload))
	p := &e.Verification.InclusionProof
	p.LogIndex, p.TreeSize, p.RootHash = int64(index), int64(size), hex.EncodeToString(root)
	for _, h := range path(index, leaves) {
		p.Hashes = append(p.Hashes, hex.EncodeToString(h))
	}
	p.Checkpoint = r.checkpoint(size, root)
	out, _ := json.Marshal(map[string]RekorEntry{"24296fb24b8ad77a" + sum(body)[:48]: e})
	return out
}

type rekorFixture struct {
	f     fixture
	rk    *fakeRekor
	pem   []byte
	resp  []byte
	entry *RekorEntry
	uuid  string
}

func newRekorFixture(t *testing.T) rekorFixture {
	f := newFixture(t, nil)
	der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	rk := newFakeRekor(t)
	resp := rk.entry(t, f.statement, f.sig, p, 5, 13)
	uuid, e, err := ParseRekorResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	return rekorFixture{f: f, rk: rk, pem: p, resp: resp, entry: e, uuid: uuid}
}

func (r rekorFixture) verify(e *RekorEntry) error {
	_, err := VerifyRekor(r.uuid, e, r.f.statement, r.f.sig, &r.f.key.PublicKey, &r.rk.key.PublicKey)
	return err
}

func TestRekorGood(t *testing.T) {
	r := newRekorFixture(t)
	res, err := VerifyRekor(r.uuid, r.entry, r.f.statement, r.f.sig, &r.f.key.PublicKey, &r.rk.key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if res.TreeSize != 13 || res.LogIndex != 900000005 || res.IntegratedTime.Unix() != 1763215400 {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestRekorRejects(t *testing.T) {
	cases := map[string]func(r *rekorFixture, e *RekorEntry){
		"other log key": func(r *rekorFixture, e *RekorEntry) { r.rk = newFakeRekor(t) },
		"moved time":    func(_ *rekorFixture, e *RekorEntry) { e.IntegratedTime++ },
		"moved index":   func(_ *rekorFixture, e *RekorEntry) { e.LogIndex++ },
		"bad SET": func(_ *rekorFixture, e *RekorEntry) {
			e.Verification.SignedEntryTimestamp = base64.StdEncoding.EncodeToString([]byte("x"))
		},
		"proof hash": func(_ *rekorFixture, e *RekorEntry) {
			e.Verification.InclusionProof.Hashes[0] = strings.Repeat("0", 64)
		},
		"proof index": func(_ *rekorFixture, e *RekorEntry) { e.Verification.InclusionProof.LogIndex = 6 },
		"short proof": func(_ *rekorFixture, e *RekorEntry) {
			h := e.Verification.InclusionProof.Hashes
			e.Verification.InclusionProof.Hashes = h[:len(h)-1]
		},
		"root hash": func(_ *rekorFixture, e *RekorEntry) {
			e.Verification.InclusionProof.RootHash = strings.Repeat("ab", 32)
		},
		"checkpoint size": func(_ *rekorFixture, e *RekorEntry) {
			c := &e.Verification.InclusionProof.Checkpoint
			*c = strings.Replace(*c, "\n13\n", "\n14\n", 1)
		},
		"checkpoint sig": func(r *rekorFixture, e *RekorEntry) {
			// Re-sign the checkpoint with another key that claims the same name.
			other := newFakeRekor(t)
			root, _ := hex.DecodeString(e.Verification.InclusionProof.RootHash)
			e.Verification.InclusionProof.Checkpoint = other.checkpoint(13, root)
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRekorFixture(t)
			edit(&r, r.entry)
			if err := r.verify(r.entry); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRekorEntryForOtherStatement(t *testing.T) {
	// A valid log entry, but for a different statement signed by the same key.
	r := newRekorFixture(t)
	other := newFixture(t, func(s *Statement) { s.AMIID = "ami-0fedcba9876543210" })
	sig := sign(t, r.f.key, other.statement)
	resp := r.rk.entry(t, other.statement, sig, r.pem, 2, 7)
	uuid, e, _ := ParseRekorResponse(resp)
	if _, err := VerifyRekor(uuid, e, r.f.statement, r.f.sig, &r.f.key.PublicKey, &r.rk.key.PublicKey); err == nil ||
		!strings.Contains(err.Error(), "statement hash") {
		t.Fatalf("got %v, want statement hash mismatch", err)
	}
}

func TestRekorEntryWithOtherSigningKey(t *testing.T) {
	// The same statement logged with a key that is not the pinned one.
	r := newRekorFixture(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	resp := r.rk.entry(t, r.f.statement, sign(t, k, r.f.statement), p, 0, 1)
	uuid, e, _ := ParseRekorResponse(resp)
	if _, err := VerifyRekor(uuid, e, r.f.statement, r.f.sig, &r.f.key.PublicKey, &r.rk.key.PublicKey); err == nil {
		t.Fatal("accepted an entry from another signing key")
	}
}

func TestParseRekorResponse(t *testing.T) {
	if _, _, err := ParseRekorResponse([]byte(`{}`)); err == nil {
		t.Fatal("accepted empty response")
	}
	if _, _, err := ParseRekorResponse([]byte(`{"a":{},"b":{}}`)); err == nil {
		t.Fatal("accepted two entries")
	}
}
