//go:build simulator

package verifier

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"log"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"

	"nodetrust/pkg/agent"
	"nodetrust/pkg/attest"
	"nodetrust/pkg/ima"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/manifest"
	"nodetrust/pkg/provider"
	"nodetrust/pkg/provider/fake"
	"nodetrust/pkg/trust"
)

type staticInventory struct{ ws []Worker }

func (s *staticInventory) Workers(context.Context) ([]Worker, error) { return s.ws, nil }

type mapManifests map[string]*manifest.Trusted

func (m mapManifests) Trusted(_ context.Context, ami string) (*manifest.Trusted, error) {
	if t := m[ami]; t != nil {
		return t, nil
	}
	return nil, errors.New("no verified manifest")
}

type countingEK struct {
	provider.EndorsementProvider
	n atomic.Int32
}

func (c *countingEK) EKPublic(ctx context.Context, id provider.InstanceID, kt provider.EKKeyType) (crypto.PublicKey, error) {
	c.n.Add(1)
	return c.EndorsementProvider.EKPublic(ctx, id, kt)
}

func TestDaemonOnSimulator(t *testing.T) {
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

	dir := t.TempDir()
	logPath := filepath.Join(dir, "ima.bin")
	extend := func(files [][2]string) {
		b := imaLog(files)
		f, _ := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		f.Write(b)
		f.Close()
		es, _ := ima.ParseLog(b)
		for _, e := range es {
			d := sha256.Sum256(e.TemplateData)
			if _, err := (tpm2.PCRExtend{
				PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(10), Auth: tpm2.PasswordAuth(nil)},
				Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
			}).Execute(sim); err != nil {
				t.Fatal(err)
			}
		}
	}
	extend([][2]string{{"boot_aggregate", "a"}, {"/usr/bin/kubelet", "kubelet"}, {"/usr/local/bin/nodetrust-agent", "agent"}})
	iidPath := filepath.Join(dir, "instance-id")
	os.WriteFile(iidPath, []byte("i-good\n"), 0o644)

	ca := newCA(t, "nodetrust verifier CA")
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv, err := agent.NewServer(tpm, agent.ServerConfig{IMALog: logPath, InstanceIDFile: iidPath})
	if err != nil {
		t.Fatal(err)
	}
	hs := srv.HTTPServer("", pool)
	ts := httptest.NewUnstartedServer(hs.Handler)
	ts.TLS = hs.TLSConfig
	ts.StartTLS()
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "https://")

	// The cloud: the real EK for i-good, another key for i-wrongek (an
	// instance whose agent is answered by a different TPM).
	ekPub, _ := attest.ParsePublic(tpm.EK.Public)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	fe := fake.NewEndorsement()
	fe.SetEK("i-good", provider.EKRSA2048, ekPub.Key)
	fe.SetEK("i-wrongek", provider.EKRSA2048, &other.PublicKey)
	ek := &countingEK{EndorsementProvider: fe}

	idx := map[string]manifest.Entry{
		"/usr/bin/kubelet":               {Path: "/usr/bin/kubelet", Type: "file", SHA256: hexsum("kubelet")},
		"/usr/local/bin/nodetrust-agent": {Path: "/usr/local/bin/nodetrust-agent", Type: "file", SHA256: hexsum("agent")},
	}
	inv := &staticInventory{ws: []Worker{
		{InstanceID: "i-good", Addr: addr, AMI: "ami-golden"},
		{InstanceID: "i-badami", Addr: addr, AMI: "ami-stock"},
		{InstanceID: "i-wrongek", Addr: addr, AMI: "ami-golden"},
		{InstanceID: "i-unsigned", Addr: addr, AMI: "ami-unsigned"},
	}}
	state := t.TempDir()
	newDaemon := func() *Daemon {
		return &Daemon{
			Inventory: inv, Endorsement: ek,
			Manifests:     mapManifests{"ami-golden": {Index: idx}},
			AllowedAMIs:   map[string]bool{"ami-golden": true, "ami-unsigned": true},
			RuntimePolicy: &imapolicy.Policy{},
			Cert:          ca.issue(t, agent.VerifierClientName),
			StateDir:      state,
			Log:           log.New(os.Stderr, "daemon: ", 0),
		}
	}
	states := func(d *Daemon) map[string]NodeStatus {
		m := map[string]NodeStatus{}
		for _, n := range d.Status() {
			m[n.InstanceID] = n
		}
		return m
	}
	ctx := context.Background()

	// Round 1: enroll and judge.
	d := newDaemon()
	if err := d.Round(ctx); err != nil {
		t.Fatal(err)
	}
	s := states(d)
	if g := s["i-good"]; g.Tier != trust.Healthy || g.Score != 100 || g.Critical || g.Unattested {
		t.Errorf("i-good after round 1: %+v", g)
	}
	if b := s["i-badami"]; b.Tier != "" {
		t.Errorf("a refused node has a tier: %q", b.Tier)
	}
	want := map[string]string{"i-good": StateVerified, "i-badami": StateRefused, "i-wrongek": StateEnrollFailed, "i-unsigned": StateRefused}
	for id, st := range want {
		if s[id].State != st {
			t.Errorf("%s: %s (%s), want %s", id, s[id].State, s[id].Reason, st)
		}
	}
	if !strings.Contains(s["i-badami"].Reason, "not on the allow-list") || !strings.Contains(s["i-wrongek"].Reason, "EK") {
		t.Errorf("reasons: %q / %q", s["i-badami"].Reason, s["i-wrongek"].Reason)
	}
	if n := ek.n.Load(); n != 2 { // i-good and i-wrongek; the refused ones are never looked up
		t.Errorf("%d EK lookups, want 2", n)
	}
	if _, err := os.Stat(filepath.Join(state, "status.json")); err != nil {
		t.Fatal(err)
	}

	// Round 2: no new enrollment for i-good (i-wrongek is retried).
	if err := d.Round(ctx); err != nil {
		t.Fatal(err)
	}
	if n := ek.n.Load(); n != 3 {
		t.Errorf("%d EK lookups after round 2, want 3", n)
	}

	// An unknown binary runs: the next quote shows it, -10 in system binaries.
	extend([][2]string{{"/tmp/.x/miner", "miner"}})
	d.Round(ctx)
	if g := states(d)["i-good"]; g.State != StateVerified || len(g.Files) != 1 || g.Files[0].Path != "/tmp/.x/miner" ||
		g.Tier != trust.Warning || g.Score != 90 || g.Critical {
		t.Fatalf("after the miner: %+v", g)
	}

	// kubelet is replaced and restarted: critical.
	extend([][2]string{{"/usr/bin/kubelet", "evil"}})
	d.Round(ctx)
	if g := states(d)["i-good"]; !g.Critical || len(g.Findings) != 1 || g.Findings[0].Type != trust.CriticalBinary {
		t.Fatalf("after kubelet: %+v", g)
	}

	// A restart keeps the enrollment (no EK lookup for i-good) and the record.
	before := ek.n.Load()
	d = newDaemon()
	d.Round(ctx)
	if g := states(d)["i-good"]; g.State != StateVerified || !g.Enrolled || ek.n.Load() != before+1 ||
		!g.Critical || g.Tier != trust.Warning || g.Score != 90 {
		t.Fatalf("after restart: %+v, EK lookups %d -> %d", g, before, ek.n.Load())
	}
	var tr Track
	if err := readJSONFile(filepath.Join(state, "track", "i-good.json"), &tr); err != nil || tr.Cycles < 5 || !tr.Critical {
		t.Fatalf("saved track: %+v %v", tr, err)
	}

	// The only enrolled node stops answering: every enrolled node failed, so
	// the round is treated as an outage and nothing is counted (8.4).
	addrGood := inv.ws[0].Addr
	inv.ws[0].Addr = "127.0.0.1:1"
	d.Round(ctx)
	if g := states(d)["i-good"]; g.State != StateOutage || g.FailStreak != 0 {
		t.Fatalf("outage: %+v", g)
	}
	inv.ws[0].Addr = addrGood

	// A stored AK that is not this TPM's: the quote does not verify.
	p := filepath.Join(state, "enrolled", "i-good.json")
	var e Enrolled
	readJSONFile(p, &e)
	e.AKPublic[len(e.AKPublic)-1] ^= 1
	writeJSONFile(p, &e)
	d = newDaemon()
	d.Round(ctx)
	if g := states(d)["i-good"]; g.State != StateBadEvidence {
		t.Fatalf("with a wrong AK: %+v", g)
	}

	// The instance is terminated: it leaves the inventory and its record goes.
	inv.ws = inv.ws[1:]
	d.Round(ctx)
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("enrolled record kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, "track", "i-good.json")); !os.IsNotExist(err) {
		t.Fatalf("track kept: %v", err)
	}
	if _, ok := states(d)["i-good"]; ok {
		t.Fatal("status kept for a terminated instance")
	}
}
