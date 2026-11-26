package controller

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"nodetrust/pkg/nodetrust"
	"nodetrust/pkg/provider"
	"nodetrust/pkg/provider/fake"
	"nodetrust/pkg/trust"
)

type env struct {
	t     *testing.T
	k     *MemKube
	cloud *fake.Containment
	c     *Controller
	key   *ecdsa.PrivateKey
	now   time.Time
	seq   map[string]uint64
}

func newEnv(t *testing.T, ids ...string) *env {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	e := &env{t: t, k: NewMemKube(), cloud: fake.NewContainment(), key: key,
		now: time.Date(2026, 11, 19, 20, 0, 0, 0, time.UTC), seq: map[string]uint64{}}
	for _, id := range ids {
		e.k.AddNode(id)
		e.cloud.AddInstance(provider.InstanceID(id))
	}
	e.c = &Controller{Kube: e.k, Cloud: e.cloud, Pub: &key.PublicKey, Cfg: DefaultConfig, StateDir: t.TempDir(),
		Now: func() time.Time { return e.now }, Logf: t.Logf}
	if err := e.c.Load(); err != nil {
		t.Fatal(err)
	}
	return e
}

// publish puts a signed state for id, as the verifier would.
func (e *env) publish(id, tier string, score float64, critical bool) {
	e.seq[id]++
	st := &nodetrust.State{InstanceID: id, Seq: e.seq[id], IssuedAt: e.now, Tier: tier, Score: score, Critical: critical, State: "verified"}
	if critical {
		st.Findings = []trust.Finding{{Type: trust.CriticalBinary, Path: "/usr/bin/kubelet", Detail: "mismatch"}}
	}
	s, err := nodetrust.Sign(e.key, st)
	if err != nil {
		e.t.Fatal(err)
	}
	e.k.NTs[id] = s
}

// allHealthy publishes a healthy state for every node.
func (e *env) allHealthy() {
	for _, n := range e.k.NodeMap {
		e.publish(n.InstanceID(), trust.Healthy, 100, false)
	}
}

func (e *env) round() {
	e.t.Helper()
	if err := e.c.Reconcile(context.Background()); err != nil {
		e.t.Fatalf("reconcile: %v", err)
	}
}

func (e *env) taints(id string) string {
	n := e.k.NodeMap["ip-"+id]
	if n == nil {
		return "(deleted)"
	}
	var ks []string
	for _, t := range n.Taints {
		ks = append(ks, strings.TrimPrefix(t.Key, Prefix)+":"+t.Effect)
	}
	if n.Unschedulable {
		ks = append(ks, "cordoned")
	}
	return strings.Join(ks, ",")
}

func (e *env) want(id, taints string) {
	e.t.Helper()
	if got := e.taints(id); got != taints {
		e.t.Fatalf("%s: %q, want %q", id, got, taints)
	}
}

func cloudCalls(c *fake.Containment) string {
	var s []string
	for _, x := range c.Calls() {
		s = append(s, x.Method)
	}
	return strings.Join(s, ",")
}

func TestScorePath(t *testing.T) {
	e := newEnv(t, "i-a", "i-b", "i-c", "i-d")
	e.round()
	e.want("i-a", "unattested:NoSchedule") // no NodeTrust yet: the join taint stays

	for _, id := range []string{"i-a", "i-b", "i-c", "i-d"} {
		e.publish(id, trust.Healthy, 100, false)
	}
	e.round()
	e.want("i-a", "")

	e.publish("i-a", trust.Warning, 90, false)
	e.round()
	e.want("i-a", "warning:PreferNoSchedule")

	e.k.Pods["ip-i-a"] = []Pod{{Namespace: "prod", Name: "db", Labels: map[string]string{LabelSensitive: "true"}}, {Namespace: "prod", Name: "web"}}
	e.publish("i-a", trust.Degraded, 72.5, false)
	e.round()
	e.want("i-a", "degraded:NoSchedule,cordoned")
	if !strings.Contains(strings.Join(e.k.Calls, ","), "evict prod/db") || strings.Contains(strings.Join(e.k.Calls, ","), "evict prod/web") {
		t.Fatalf("evictions: %v", e.k.Calls)
	}

	e.publish("i-a", trust.Healthy, 100, false) // a corrected manifest raised it
	e.round()
	e.want("i-a", "")
	if cloudCalls(e.cloud) != "" {
		t.Fatalf("no AWS call expected on the score path: %s", cloudCalls(e.cloud))
	}
}

func TestUncordonOnlyOurs(t *testing.T) {
	e := newEnv(t, "i-a")
	e.k.NodeMap["ip-i-a"].Unschedulable = true // an operator cordoned it
	e.publish("i-a", trust.Healthy, 100, false)
	e.round()
	e.want("i-a", "cordoned")
}

func TestCriticalPath(t *testing.T) {
	e := newEnv(t, "i-a", "i-b", "i-c", "i-d")
	for _, id := range []string{"i-a", "i-b", "i-c", "i-d"} {
		e.publish(id, trust.Healthy, 100, false)
	}
	e.round()
	e.k.Pods["ip-i-a"] = []Pod{{Namespace: "prod", Name: "db", Secrets: []string{"db-password"}, ServiceAccount: "db"}}
	e.publish("i-a", trust.Healthy, 100, true)
	e.round()
	if got := cloudCalls(e.cloud); got != "Isolate,Snapshot,Replace" {
		t.Fatalf("AWS calls %s", got)
	}
	e.want("i-a", "(deleted)")
	r := e.c.recs["i-a"]
	if r.Phase != PhaseReleased || len(r.Snapshots) == 0 || strings.Join(r.Secrets, ",") != "prod/db-password,prod/serviceaccount:db" {
		t.Fatalf("record %+v", r)
	}
	// The node is never returned, even if a healthy update follows.
	e.publish("i-a", trust.Healthy, 100, false)
	e.round()
	if got := cloudCalls(e.cloud); got != "Isolate,Snapshot,Replace" {
		t.Fatalf("AWS calls after release %s", got)
	}
	e.want("i-b", "")
}

func TestUntrustedIsCritical(t *testing.T) {
	e := newEnv(t, "i-a", "i-b", "i-c", "i-d")
	e.allHealthy()
	e.publish("i-a", trust.Untrusted, 40, false)
	e.round()
	if got := cloudCalls(e.cloud); got != "Isolate,Snapshot,Replace" {
		t.Fatalf("AWS calls %s", got)
	}
}

func TestStep1BeforeAWSAndRetry(t *testing.T) {
	e := newEnv(t, "i-a", "i-b", "i-c", "i-d")
	e.allHealthy()
	e.publish("i-a", trust.Healthy, 100, true)
	e.k.FailPatch = fmt.Errorf("API server down")
	if err := e.c.Reconcile(context.Background()); err == nil {
		t.Fatal("want an error")
	}
	if got := cloudCalls(e.cloud); got != "" {
		t.Fatalf("isolation before cordon: %s", got)
	}
	e.k.FailPatch = nil
	e.round()
	if got := cloudCalls(e.cloud); got != "Isolate,Snapshot,Replace" {
		t.Fatalf("AWS calls %s", got)
	}
}

func TestBadUpdatesIgnored(t *testing.T) {
	e := newEnv(t, "i-a", "i-b")
	e.publish("i-a", trust.Healthy, 100, false)
	e.publish("i-b", trust.Healthy, 100, false)
	e.round()
	good := e.k.NTs["i-a"]

	// Signed with another key: ignored, the last good state stays.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	st := &nodetrust.State{InstanceID: "i-a", Seq: 99, IssuedAt: e.now, Tier: trust.Untrusted, Critical: true}
	e.k.NTs["i-a"], _ = nodetrust.Sign(other, st)
	e.round()
	// Replayed old state, and another node's state copied in.
	e.k.NTs["i-a"] = good
	e.round()
	e.k.NTs["i-a"] = e.k.NTs["i-b"]
	e.round()
	if got := cloudCalls(e.cloud); got != "" {
		t.Fatalf("acted on a bad update: %s", got)
	}
	if r := e.c.recs["i-a"]; r.BadUpdates != 2 || r.State.Tier != trust.Healthy {
		// the replay of the payload already accepted is not new, so 2 bad
		t.Fatalf("record %+v", r)
	}
	e.want("i-a", "")
}

func TestOutageHoldsActions(t *testing.T) {
	e := newEnv(t, "i-a", "i-b")
	e.publish("i-a", trust.Healthy, 100, false)
	e.publish("i-b", trust.Healthy, 100, false)
	e.round()
	e.now = e.now.Add(10 * time.Minute) // the verifier stopped publishing
	e.round()
	e.want("i-a", "")
	e.want("i-b", "")
	if !e.c.outage {
		t.Fatal("outage not seen")
	}
	// One node fresh again, the other still silent: that one is unattested.
	e.publish("i-a", trust.Healthy, 100, false)
	e.round()
	e.want("i-a", "")
	e.want("i-b", "unattested:NoSchedule")
}

func TestCircuitBreaker(t *testing.T) {
	// Two workers: one critical node is 50% of the fleet, over 30%.
	e := newEnv(t, "i-a", "i-b")
	e.publish("i-a", trust.Healthy, 100, true)
	e.publish("i-b", trust.Healthy, 100, false)
	e.round()
	e.want("i-a", "critical:NoExecute,cordoned")
	if got := cloudCalls(e.cloud); got != "" || e.c.recs["i-a"].Phase != PhaseHeld || !e.c.breaker {
		t.Fatalf("not held: calls %s phase %s", got, e.c.recs["i-a"].Phase)
	}
	e.round()
	if err := Approve(e.c.StateDir, "i-a"); err != nil {
		t.Fatal(err)
	}
	e.round()
	if got := cloudCalls(e.cloud); got != "Isolate,Snapshot,Replace" {
		t.Fatalf("after approval: %s", got)
	}
}

func TestDryRun(t *testing.T) {
	e := newEnv(t, "i-a", "i-b", "i-c", "i-d")
	e.c.Cfg.DryRun = true
	for _, id := range []string{"i-a", "i-b", "i-c", "i-d"} {
		e.publish(id, trust.Healthy, 100, false)
	}
	e.publish("i-b", trust.Warning, 90, false)
	e.publish("i-a", trust.Healthy, 100, true)
	e.round()
	e.round()
	if len(e.k.Calls) != 0 || cloudCalls(e.cloud) != "" {
		t.Fatalf("dry-run changed something: %v %s", e.k.Calls, cloudCalls(e.cloud))
	}
	var lines []string
	for _, ev := range append(e.c.recs["i-a"].Events, e.c.recs["i-b"].Events...) {
		lines = append(lines, ev.Text)
	}
	got := strings.Join(lines, "\n")
	for _, w := range []string{
		"dry-run: would trust taints critical:NoExecute",
		"dry-run: would cordon",
		"dry-run: would isolate: quarantine security group and NACL deny",
		"dry-run: would snapshot the EBS volumes",
		"dry-run: would replace: detach from the Auto Scaling group (desired capacity kept)",
		"dry-run: would release workloads: delete the Node object",
		"dry-run: (warning, score 90)",
		"dry-run: would trust taints warning:PreferNoSchedule", // replaces the join taint
	} {
		if !strings.Contains(got, w) {
			t.Fatalf("missing %q in\n%s", w, got)
		}
	}
	if strings.Count(got, "would isolate") != 1 {
		t.Fatalf("plan logged more than once:\n%s", got)
	}
}

func TestRestartContinues(t *testing.T) {
	e := newEnv(t, "i-a", "i-b")
	e.publish("i-a", trust.Healthy, 100, true)
	e.publish("i-b", trust.Healthy, 100, false)
	e.round() // held by the breaker
	c2 := &Controller{Kube: e.k, Cloud: e.cloud, Pub: &e.key.PublicKey, Cfg: DefaultConfig, StateDir: e.c.StateDir, Now: e.c.Now}
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}
	if c2.recs["i-a"].Phase != PhaseHeld {
		t.Fatalf("phase after restart: %+v", c2.recs["i-a"])
	}
	Approve(e.c.StateDir, "i-a")
	e.c = c2
	e.round()
	if got := cloudCalls(e.cloud); got != "Isolate,Snapshot,Replace" {
		t.Fatalf("after restart: %s", got)
	}
}

func TestDryRunCriticalForgottenWhenLive(t *testing.T) {
	e := newEnv(t, "i-a", "i-b", "i-c", "i-d")
	e.allHealthy()
	e.c.Cfg.DryRun = true
	e.publish("i-a", trust.Healthy, 100, true)
	e.round()
	live := &Controller{Kube: e.k, Cloud: e.cloud, Pub: &e.key.PublicKey, Cfg: DefaultConfig, StateDir: e.c.StateDir, Now: e.c.Now}
	if err := live.Load(); err != nil {
		t.Fatal(err)
	}
	if !live.recs["i-a"].CriticalAt.IsZero() {
		t.Fatal("dry-run critical time kept")
	}
	e.c = live
	e.round()
	if got := cloudCalls(e.cloud); got != "Isolate,Snapshot,Replace" {
		t.Fatalf("live after dry-run: %s", got)
	}
}

// kubeadm labels the control plane node with an empty value; it must not
// be managed as a worker (found in the live dry run).
func TestControlPlaneNotManaged(t *testing.T) {
	e := newEnv(t, "i-a", "i-cp")
	e.k.NodeMap["ip-i-cp"].Labels["node-role.kubernetes.io/control-plane"] = ""
	e.k.NodeMap["ip-i-cp"].Taints = nil
	e.publish("i-a", trust.Healthy, 100, false)
	e.round()
	e.want("i-cp", "")
	if _, ok := e.c.recs["i-cp"]; ok {
		t.Fatal("control plane node has a record")
	}
}

// A restarted controller logs its current dry-run plan again (found in the
// live dry run: the check reads the log of the current run only).
func TestDryRunPlanLoggedAfterRestart(t *testing.T) {
	e := newEnv(t, "i-a")
	e.c.Cfg.DryRun = true
	e.publish("i-a", trust.Healthy, 100, false)
	e.round()
	c2 := &Controller{Kube: e.k, Cloud: e.cloud, Pub: &e.key.PublicKey, Cfg: e.c.Cfg, StateDir: e.c.StateDir, Now: e.c.Now}
	if err := c2.Load(); err != nil {
		t.Fatal(err)
	}
	n := len(c2.recs["i-a"].Events)
	e.c = c2
	e.round()
	if got := c2.recs["i-a"].Events[n:]; len(got) == 0 || !strings.Contains(got[len(got)-1].Text, "would trust taints removed") {
		t.Fatalf("not logged again: %+v", got)
	}
}

// Node objects of terminated instances (NotReady, no NodeTrust) do not
// count as workers for the circuit breaker (found in the live dry run:
// eight stale nodes made 1 critical of 2 look like 1 of 10).
func TestBreakerCountsAttestedWorkersOnly(t *testing.T) {
	e := newEnv(t, "i-a", "i-b")
	for i := 0; i < 8; i++ {
		e.k.AddNode(fmt.Sprintf("i-old%d", i))
	}
	e.publish("i-a", trust.Healthy, 100, true)
	e.publish("i-b", trust.Healthy, 100, false)
	e.round()
	if e.c.recs["i-a"].Phase != PhaseHeld {
		t.Fatalf("phase %q: the stale nodes diluted the breaker", e.c.recs["i-a"].Phase)
	}
}

func TestControllerMetrics(t *testing.T) {
	e := newEnv(t, "i-a", "i-b")
	e.c.Metrics = NewMetrics()
	e.c.Metrics.Collect(e.c.Collect)
	e.publish("i-a", trust.Healthy, 100, true)
	e.publish("i-b", trust.Healthy, 100, false)
	e.round() // held by the breaker
	var b bytes.Buffer
	e.c.Metrics.Write(&b)
	for _, want := range []string{
		`node_containment_phase{node="i-a",phase="held"} 1`,
		`node_containment_phase{node="i-a",phase="isolated"} 0`,
		`trust_circuit_breaker_open 1`,
		`node_containment_step_seconds_count{step="cordoned"} 1`,
	} {
		if !strings.Contains(b.String(), want+"\n") {
			t.Fatalf("missing %s in\n%s", want, b.String())
		}
	}
	Approve(e.c.StateDir, "i-a")
	e.now = e.now.Add(90 * time.Second)
	e.round()
	b.Reset()
	e.c.Metrics.Write(&b)
	for _, want := range []string{
		`node_containment_phase{node="i-a",phase="released"} 1`,
		`trust_circuit_breaker_open 0`,
		`node_containment_step_seconds_bucket{step="isolated",le="60"} 0`,
		`node_containment_step_seconds_bucket{step="isolated",le="120"} 1`,
	} {
		if !strings.Contains(b.String(), want+"\n") {
			t.Fatalf("missing %s in\n%s", want, b.String())
		}
	}
}

// An instance terminated by someone else before containment finished (the
// Phase 7 A15 run 2) stops the retries: one event, phase gone, Node deleted.
func TestTerminatedElsewhereStops(t *testing.T) {
	e := newEnv(t, "i-a", "i-b", "i-c", "i-d")
	e.allHealthy()
	e.cloud.Kill("i-a")
	e.publish("i-a", trust.Healthy, 100, true)
	e.round()
	e.round()
	e.round()
	r := e.c.recs["i-a"]
	if r.Phase != PhaseGone {
		t.Fatalf("phase %q, want gone", r.Phase)
	}
	if got := cloudCalls(e.cloud); got != "Isolate" {
		t.Fatalf("AWS calls %s, want one try", got)
	}
	e.want("i-a", "(deleted)")
	e.want("i-b", "")
}

// The same error in every round is recorded once.
func TestRepeatedErrorRecordedOnce(t *testing.T) {
	e := newEnv(t, "i-a", "i-b", "i-c", "i-d")
	e.allHealthy()
	e.publish("i-a", trust.Healthy, 100, true)
	e.k.FailPatch = fmt.Errorf("API server down")
	for i := 0; i < 5; i++ {
		e.c.Reconcile(context.Background())
	}
	n := 0
	for _, ev := range e.c.recs["i-a"].Events {
		if strings.HasPrefix(ev.Text, "error: ") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d error events, want 1", n)
	}
}
