//go:build simulator

package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"nodetrust/pkg/agent"
	"nodetrust/pkg/attest"
	"nodetrust/pkg/ima"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T, name string) *testCA {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{c, k}
}

func (ca *testCA) issue(t *testing.T, cn string) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

func TestAgentServiceOverMTLS(t *testing.T) {
	sim, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatal(err)
	}
	defer sim.Close()
	tpm, err := agent.New(sim)
	if err != nil {
		t.Fatal(err)
	}
	defer tpm.Close()

	// An IMA log, extended into PCR 10.
	dir := t.TempDir()
	logBytes := imaLog([][2]string{{"boot_aggregate", "a"}, {"/usr/local/bin/nodetrust-agent", "agent"}})
	logPath := filepath.Join(dir, "ima.bin")
	os.WriteFile(logPath, logBytes, 0o600)
	es, _ := ima.ParseLog(logBytes)
	for _, e := range es {
		d := sha256.Sum256(e.TemplateData)
		if _, err := (tpm2.PCRExtend{
			PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(10), Auth: tpm2.PasswordAuth(nil)},
			Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
		}).Execute(sim); err != nil {
			t.Fatal(err)
		}
	}
	iidPath := filepath.Join(dir, "instance-id")
	os.WriteFile(iidPath, []byte("i-sim\n"), 0o644)

	ca := newCA(t, "nodetrust verifier CA")
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	countPath := filepath.Join(dir, "count")
	os.WriteFile(countPath, []byte("2\n"), 0o600)
	srv, err := agent.NewServer(tpm, agent.ServerConfig{IMALog: logPath, InstanceIDFile: iidPath,
		CanaryPath: filepath.Join(dir, "canary"), IMACount: countPath, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	hs := srv.HTTPServer("", pool)
	ts := httptest.NewUnstartedServer(hs.Handler)
	ts.TLS = hs.TLSConfig
	ts.StartTLS()
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "https://")

	ekPub, _ := attest.ParsePublic(tpm.EK.Public)
	ctx := context.Background()

	// The verifier enrolls and gets a bound quote.
	c := NewClient(addr, ca.issue(t, agent.VerifierClientName))
	enr, err := c.Enroll(ctx, "i-sim", ekPub.Key)
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Quote(ctx, enr, QuoteOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.IMA.Attested != 2 || !res.Next.Valid || res.Next.Entries != 2 || res.Next.Offset != int64(len(logBytes)) {
		t.Fatalf("replay %+v, next %+v", res.IMA, res.Next)
	}

	// The next challenge: one new measurement, sent from the verified
	// offset, with the canary, a sweep and the mount audit.
	more := imaLog([][2]string{{"/usr/bin/new", "x"}})
	f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o600)
	f.Write(more)
	f.Close()
	es2, _ := ima.ParseLog(more)
	d := sha256.Sum256(es2[0].TemplateData)
	if _, err := (tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(10), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
	}).Execute(sim); err != nil {
		t.Fatal(err)
	}
	sweepDir := filepath.Join(dir, "sweep")
	os.MkdirAll(sweepDir, 0o700)
	os.WriteFile(filepath.Join(sweepDir, "a"), []byte("a"), 0o600)
	res2, err := c.Quote(ctx, enr, QuoteOptions{State: res.Next, Canary: true, Sweep: []string{sweepDir}, SweepMS: 2000, Mounts: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.IMAEntries) != 1 || res2.Next.Entries != 3 || res2.Next.Offset != int64(len(logBytes)+len(more)) ||
		res2.CanaryStatus != "ok" || len(res2.Canary) != 32 || res2.Sweep == nil || res2.Sweep.Opened != 1 ||
		res2.Mounts == nil || len(res2.Mounts.Namespaces) == 0 || res2.AgentVersion != "test" {
		t.Fatalf("incremental: %d entries, next %+v, canary %q, sweep %+v, mounts %v", len(res2.IMAEntries), res2.Next, res2.CanaryStatus, res2.Sweep, res2.Mounts != nil)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "canary")); string(b) != string(res2.Canary) {
		t.Fatal("canary file does not hold the challenge's value")
	}
	// Nothing new since: the replay starts and ends at the same value.
	res3, err := c.Quote(ctx, enr, QuoteOptions{State: res2.Next})
	if err != nil || len(res3.IMAEntries) != 0 || res3.Next.Entries != 3 {
		t.Fatalf("no new entries: %v %+v", err, res3)
	}
	// A state from another boot (another resetCount): the client asks again
	// for the whole log.
	stale := res2.Next
	stale.ResetCount++
	res4, err := c.Quote(ctx, enr, QuoteOptions{State: stale})
	if err != nil || res4.Next.Entries != 3 || res4.Next.Offset != int64(len(logBytes)+len(more)) {
		t.Fatalf("new boot: %v %+v", err, res4)
	}
	// A state that claims more log than there is, in the same boot: the
	// agent sends from 0, which the verifier refuses as evidence.
	bad := res2.Next
	bad.Offset += 1 << 20
	var ee *EvidenceError
	if _, err := c.Quote(ctx, enr, QuoteOptions{State: bad}); !errors.As(err, &ee) {
		t.Fatalf("shrunk log: %v", err)
	}

	// Hints: the count file says 3; asking with 2 answers at once.
	os.WriteFile(countPath, []byte("3\n"), 0o600)
	if n, err := c.Hint(ctx, 2); err != nil || n != 3 {
		t.Fatalf("hint: %d %v", n, err)
	}

	// Clients the agent must refuse.
	for name, cert := range map[string]tls.Certificate{
		"rogue CA":       newCA(t, "rogue").issue(t, agent.VerifierClientName),
		"wrong name":     ca.issue(t, "some-pod"),
		"no client cert": {},
	} {
		if _, err := NewClient(addr, cert).Enroll(ctx, "i-sim", ekPub.Key); err == nil {
			t.Errorf("%s: agent answered", name)
		}
	}

	// A man in the middle: terminates TLS with its own key and relays to the
	// agent with a valid client certificate. Enrollment still works (only
	// the TPM can produce the secret), but the quote binding exposes it.
	target, _ := url.Parse(ts.URL)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, Certificates: []tls.Certificate{ca.issue(t, agent.VerifierClientName)},
	}}
	mitm := httptest.NewTLSServer(proxy)
	defer mitm.Close()
	mc := NewClient(strings.TrimPrefix(mitm.URL, "https://"), ca.issue(t, agent.VerifierClientName))
	if _, err := mc.Quote(ctx, enr, QuoteOptions{}); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("quote through a TLS-terminating relay: %v, want a nonce (binding) failure", err)
	}
}
