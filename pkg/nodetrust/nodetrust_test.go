package nodetrust

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nodetrust/pkg/trust"
)

var t0 = time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)

func key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func state(seq uint64) *State {
	return &State{InstanceID: "i-1", AMI: "ami-g", Seq: seq, IssuedAt: t0, Tier: trust.Warning, Score: 90,
		Files: []trust.File{{Path: "/usr/bin/yes", Class: "mismatch", Component: trust.Binaries}}, State: "verified"}
}

func TestSignVerify(t *testing.T) {
	k := key(t)
	s, err := Sign(k, state(7))
	if err != nil {
		t.Fatal(err)
	}
	st, err := Check(&k.PublicKey, s, "i-1", 6, t0.Add(time.Minute), 5*time.Minute)
	if err != nil || st.Score != 90 || st.Files[0].Path != "/usr/bin/yes" {
		t.Fatalf("%+v %v", st, err)
	}
	// Everything a writer without the key could do fails.
	tamper := func(f func(*Signed)) *Signed { c := *s; f(&c); return &c }
	payload, _ := base64.StdEncoding.DecodeString(s.Payload)
	better := strings.Replace(string(payload), `"score":90`, `"score":100`, 1)
	cases := map[string]struct {
		s       *Signed
		name    string
		lastSeq uint64
		want    string
	}{
		"score raised":      {tamper(func(c *Signed) { c.Payload = base64.StdEncoding.EncodeToString([]byte(better)) }), "i-1", 0, "does not verify"},
		"unsigned":          {&Signed{}, "i-1", 0, "unsigned"},
		"other key":         {func() *Signed { o, _ := Sign(key(t), state(7)); return o }(), "i-1", 0, "signed with key"},
		"moved to i-2":      {s, "i-2", 0, "holds the state of i-1"},
		"replayed":          {s, "i-1", 7, "not after 7"},
		"garbage signature": {tamper(func(c *Signed) { c.Signature = "AAAA" }), "i-1", 0, "does not verify"},
	}
	for name, c := range cases {
		if _, err := Check(&k.PublicKey, c.s, c.name, c.lastSeq, t0, 0); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if _, err := Check(&k.PublicKey, s, "i-1", 0, t0.Add(time.Hour), 5*time.Minute); err == nil {
		t.Error("stale state accepted")
	}
}

func TestParseKeys(t *testing.T) {
	k := key(t)
	sec1, _ := x509.MarshalECPrivateKey(k)
	p8, _ := x509.MarshalPKCS8PrivateKey(k)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	for _, b := range [][]byte{
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p8}),
	} {
		if got, err := ParsePrivateKey(b); err != nil || !got.Equal(k) {
			t.Fatal(err)
		}
	}
	if got, err := ParsePublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})); err != nil || !got.Equal(&k.PublicKey) {
		t.Fatal(err)
	}
}

// The publisher's requests: server-side apply of the object, then of its
// status, both as the verifier's field manager.
func TestPublish(t *testing.T) {
	var seen []string
	var status map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append(seen, r.Method+" "+r.URL.Path+" "+r.URL.RawQuery+" "+r.Header.Get("Content-Type"))
		if strings.HasSuffix(r.URL.Path, "/status") {
			var o map[string]any
			json.Unmarshal(b, &o)
			status = o["status"].(map[string]any)
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	k := key(t)
	p := &Publisher{Kube: &Kube{Server: srv.URL, HTTP: srv.Client()}, Key: k}
	if err := p.Publish(context.Background(), state(3)); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"PATCH /apis/trust.k8s-attest.io/v1alpha1/nodetrusts/i-1 fieldManager=nodetrust-verifier&force=true application/apply-patch+yaml",
		"PATCH /apis/trust.k8s-attest.io/v1alpha1/nodetrusts/i-1/status fieldManager=nodetrust-verifier&force=true application/apply-patch+yaml",
	}
	if strings.Join(seen, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s", strings.Join(seen, "\n"))
	}
	// What landed in the status verifies.
	sb, _ := json.Marshal(status["signed"])
	var s Signed
	json.Unmarshal(sb, &s)
	if st, err := Verify(&k.PublicKey, &s); err != nil || st.Seq != 3 || status["tier"] != "warning" {
		t.Fatalf("%+v %v %v", st, err, status)
	}
	if err := p.Remove(context.Background(), "i-1"); err != nil {
		t.Fatalf("delete of a missing object: %v", err)
	}
}

func TestApplyError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"kind":"Status","message":"nodetrusts.trust.k8s-attest.io \"i-1\" is forbidden: ValidatingAdmissionPolicy 'nodetrust-writer' denied request"}`))
	}))
	defer srv.Close()
	p := &Publisher{Kube: &Kube{Server: srv.URL, HTTP: srv.Client()}, Key: key(t)}
	if err := p.Publish(context.Background(), state(1)); err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "nodetrust-writer") {
		t.Fatal(err)
	}
}
