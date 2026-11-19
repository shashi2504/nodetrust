package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"nodetrust/pkg/ima"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/joinref"
	"nodetrust/pkg/manifest"
	"nodetrust/pkg/trust"
)

func shaOf(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func joinDaemon(t *testing.T) *Daemon {
	t.Helper()
	d := &Daemon{StateDir: t.TempDir(), RuntimePolicy: &imapolicy.Policy{}, JoinRef: &joinref.Reference{Format: joinref.Format,
		Files: map[string]joinref.File{
			"/var/lib/kubelet/config.yaml":        {Template: "kind: KubeletConfiguration\n"},
			"/etc/kubernetes/nodetrust/join.yaml": {Template: "value: aws:///${AZ}/${IID}\n"},
		},
		Consensus: []string{"/opt/cni/bin/"}}}
	if err := d.Load(); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestJoinCheck(t *testing.T) {
	d := joinDaemon(t)
	w1 := Worker{InstanceID: "i-1", Addr: "10.42.17.24:9443", AMI: "ami-g", Zone: "ap-south-1c"}
	w2 := Worker{InstanceID: "i-2", Addr: "10.42.20.120:9443", AMI: "ami-g", Zone: "ap-south-1c"}
	jc1, jc2 := d.joinCheck(w1, true), d.joinCheck(w2, true)
	check := func(jc JoinCheck, p, sha, want string) {
		t.Helper()
		c, ok := jc(p, sha)
		if !ok || c != want {
			t.Fatalf("%s %s: %s %v, want %s", p, sha[:8], c, ok, want)
		}
	}
	// Precomputed: per node.
	check(jc1, "/etc/kubernetes/nodetrust/join.yaml", shaOf("value: aws:///ap-south-1c/i-1\n"), imapolicy.Join)
	check(jc2, "/etc/kubernetes/nodetrust/join.yaml", shaOf("value: aws:///ap-south-1c/i-1\n"), imapolicy.Mismatch) // i-1's file on i-2
	check(jc1, "/var/lib/kubelet/config.yaml", shaOf("kind: KubeletConfiguration\n"), imapolicy.Join)
	check(jc1, "/var/lib/kubelet/config.yaml", shaOf("kind: KubeletConfiguration\nauthentication: {anonymous: {enabled: true}}\n"), imapolicy.Mismatch) // A10
	// Not covered.
	if _, ok := jc1("/usr/bin/ls", "aa"); ok {
		t.Fatal("covered a non-join path")
	}
	// Consensus: the first node's hash is accepted on first use; the second
	// node's different hash is flagged.
	check(jc1, "/opt/cni/bin/calico", "c0ffee", imapolicy.Join)
	check(jc2, "/opt/cni/bin/calico", "bad000", imapolicy.Mismatch)
	// Through Judge: a mismatched join file counts against the score in the
	// Kubernetes component.
	entries, _ := ima.ParseLog(imaLog([][2]string{{"/var/lib/kubelet/config.yaml", "edited"}}))
	v := Judge(&QuoteResult{IMAEntries: entries}, w1, &manifestTrusted, &imapolicy.Policy{}, nil, jc1)
	if len(v.Files) != 1 || v.Files[0].Component != trust.Kubernetes || v.Files[0].Class != imapolicy.Mismatch {
		t.Fatalf("%+v", v)
	}
	// Restart: the votes are kept.
	d2 := &Daemon{StateDir: d.StateDir, JoinRef: d.JoinRef}
	d2.Load()
	check(d2.joinCheck(w2, false), "/opt/cni/bin/calico", "c0ffee", imapolicy.Join)
}

var manifestTrusted = manifestFor()

func manifestFor() manifest.Trusted { return manifest.Trusted{Index: map[string]manifest.Entry{}} }

// A node with a remembered file: Track.Observe calls Still while the daemon
// lock is held, so Still must not take it (it did once, and the verifier
// hung on its first node with a sticky file).
func TestObserveWithStillDoesNotDeadlock(t *testing.T) {
	d := joinDaemon(t)
	w := Worker{InstanceID: "i-1", Addr: "10.42.17.24:9443", AMI: "ami-g", Zone: "ap-south-1c"}
	tr := manifestFor()
	v := verdict(it("/usr/local/bin/x", imapolicy.Unknown))
	ob := func() *outcome {
		return &outcome{w: w, obs: []Observation{{At: t0, State: StateVerified, Quote: q(1, 0, 1), Verdict: v, Still: d.stillFunc(w, &tr)}}}
	}
	done := make(chan struct{})
	go func() {
		d.observe(ob())
		d.observe(ob()) // the second call runs Still on the remembered file
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("observe deadlocked")
	}
}

func TestJoinViolation(t *testing.T) {
	d := joinDaemon(t)
	jc := d.joinCheck(Worker{InstanceID: "i-1", Addr: "10.42.17.24:9443", AMI: "ami-g"}, true)
	if c, ok := jc("/var/lib/kubelet/config.yaml", ""); !ok || c != imapolicy.Violation {
		t.Fatal(c, ok)
	}
	if c, ok := jc("/opt/cni/bin/calico", ""); !ok || c != imapolicy.Violation {
		t.Fatal(c, ok)
	}
	if _, ok := jc("/usr/bin/ls", ""); ok {
		t.Fatal("violation outside join paths covered")
	}
}

// /opt/cni/bin holds files from the AMI that Calico replaces at join: the
// AMI's version (in the manifest) and Calico's (in the join reference) are
// both accepted, anything else is a mismatch. Seen live: after a reboot a
// worker measured Calico's loopback and portmap, and consensus alone,
// which had the AMI's version first, flagged them.
func TestJoinAMIAndCalicoVersions(t *testing.T) {
	d := joinDaemon(t)
	d.JoinRef.Files["/opt/cni/bin/loopback"] = joinref.File{SHA256: []string{shaOf("calico")}}
	w := Worker{InstanceID: "i-1", Addr: "10.42.17.24:9443", AMI: "ami-g"}
	tr := manifest.Trusted{Index: map[string]manifest.Entry{
		"/opt/cni/bin/loopback": {Path: "/opt/cni/bin/loopback", Type: "file", SHA256: shaOf("ami")}}}
	for content, want := range map[string]int{"ami": 0, "calico": 0, "evil": 1} {
		entries, _ := ima.ParseLog(imaLog([][2]string{{"/opt/cni/bin/loopback", content}}))
		v := Judge(&QuoteResult{IMAEntries: entries}, w, &tr, &imapolicy.Policy{}, nil, d.joinCheck(w, true))
		if len(v.Files) != want {
			t.Errorf("%s: %+v", content, v.Files)
		}
	}
}
