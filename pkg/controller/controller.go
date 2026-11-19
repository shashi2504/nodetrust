package controller

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"nodetrust/pkg/nodetrust"
	"nodetrust/pkg/provider"
)

// Node is what the controller reads and writes of a Kubernetes Node.
type Node struct {
	Name            string
	ProviderID      string // aws:///<zone>/<instance-id>
	ResourceVersion string
	Taints          []Taint
	Unschedulable   bool
	Labels          map[string]string
	Annotations     map[string]string
}

// InstanceID is the EC2 instance of a node, from its provider ID ("" if it
// has none).
func (n Node) InstanceID() string {
	if !strings.HasPrefix(n.ProviderID, "aws:///") {
		return ""
	}
	return n.ProviderID[strings.LastIndex(n.ProviderID, "/")+1:]
}

// ControlPlane reports whether the node is a control plane node. kubeadm
// sets the label with an empty value, so only its presence counts.
func (n Node) ControlPlane() bool {
	_, ok := n.Labels["node-role.kubernetes.io/control-plane"]
	return ok
}

// Pod is what the controller needs to know about a pod on a node.
type Pod struct {
	Namespace      string
	Name           string
	Labels         map[string]string
	Secrets        []string // secret names it mounts
	ServiceAccount string
}

// Kube is the part of the Kubernetes API the controller uses.
type Kube interface {
	NodeTrusts(ctx context.Context) (map[string]*nodetrust.Signed, error)
	Nodes(ctx context.Context) ([]Node, error)
	// PatchNode sets the node's taints, cordon and annotations (nil value:
	// remove), failing if the node changed since n.ResourceVersion.
	PatchNode(ctx context.Context, n Node, taints []Taint, unschedulable bool, ann map[string]*string) error
	DeleteNode(ctx context.Context, name string) error
	PodsOn(ctx context.Context, node string) ([]Pod, error)
	Evict(ctx context.Context, namespace, name string) error
}

// Config holds the controller's settings.
type Config struct {
	DryRun          bool          // log what would be done, change nothing
	MaxAge          time.Duration // a NodeTrust update older than this is stale
	BreakerNodes    int           // more critical nodes than this in the window holds containment
	BreakerFraction float64       // or more than this fraction of the workers
	BreakerWindow   time.Duration
}

// DefaultConfig is blueprint 8.4: more than 2 nodes or 30% of the nodes in
// 10 minutes opens the circuit breaker.
var DefaultConfig = Config{MaxAge: 3 * time.Minute, BreakerNodes: 2, BreakerFraction: 0.3, BreakerWindow: 10 * time.Minute}

// Critical path phases, in order.
const (
	PhaseCordoned = "cordoned"    // step 1 done: cordon, critical taint, secrets recorded
	PhaseHeld     = "held"        // circuit breaker: waiting for an operator
	PhaseIsolated = "isolated"    // step 2: quarantine group and NACL deny
	PhaseSnapshot = "snapshotted" // step 3: EBS snapshots
	PhaseReplaced = "replaced"    // step 4: detached from the Auto Scaling group
	PhaseReleased = "released"    // step 5: Node object deleted
)

// Event is one thing the controller did or would do.
type Event struct {
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}

// Record is the controller's memory of one instance, kept across restarts.
type Record struct {
	Seq        uint64           `json:"seq"`
	Payload    string           `json:"payload"`
	State      *nodetrust.State `json:"state,omitempty"` // last update that passed the checks
	BadUpdates int              `json:"bad_updates"`
	LastBad    string           `json:"last_bad,omitempty"`

	Phase       string    `json:"phase,omitempty"`
	CriticalAt  time.Time `json:"critical_at,omitempty"`
	DryCritical bool      `json:"dry_critical,omitempty"` // CriticalAt was set in dry-run mode
	Reason      string    `json:"reason,omitempty"`
	Approved    bool      `json:"approved,omitempty"`
	Snapshots   []string  `json:"snapshots,omitempty"`
	Secrets     []string  `json:"secrets,omitempty"` // to rotate: namespace/secret, namespace/serviceaccount:name
	LastPlan    []string  `json:"last_plan,omitempty"`
	Events      []Event   `json:"events,omitempty"`
}

// Controller reconciles nodes and AWS resources from signed NodeTrust.
type Controller struct {
	Kube     Kube
	Cloud    provider.ContainmentProvider
	Pub      *ecdsa.PublicKey // pinned NodeTrust signing key
	Cfg      Config
	StateDir string // state.json, status.json, approve/<instance-id>
	Logf     func(format string, a ...any)
	Now      func() time.Time

	mu      sync.Mutex
	recs    map[string]*Record
	outage  bool
	breaker bool
}

func (c *Controller) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Controller) logf(format string, a ...any) {
	if c.Logf != nil {
		c.Logf(format, a...)
	}
}

// Load reads the saved records (none on the first start).
func (c *Controller) Load() error {
	c.recs = map[string]*Record{}
	b, err := os.ReadFile(filepath.Join(c.StateDir, "state.json"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, &c.recs); err != nil {
		return err
	}
	// After a restart every current plan is logged again once (the log of
	// this run is complete on its own).
	for _, r := range c.recs {
		r.LastPlan = nil
	}
	// A critical node seen only in dry-run neither counts for the circuit
	// breaker of a live run nor skips its first log line.
	if !c.Cfg.DryRun {
		for _, r := range c.recs {
			if r.DryCritical {
				r.CriticalAt, r.DryCritical, r.Reason, r.LastPlan = time.Time{}, false, "", nil
			}
		}
	}
	return nil
}

func (c *Controller) rec(id string) *Record {
	if c.recs == nil {
		c.recs = map[string]*Record{}
	}
	r := c.recs[id]
	if r == nil {
		r = &Record{}
		c.recs[id] = r
	}
	return r
}

func (c *Controller) event(id string, r *Record, text string) {
	r.Events = append(r.Events, Event{At: c.now().UTC(), Text: text})
	if len(r.Events) > 40 {
		r.Events = r.Events[len(r.Events)-40:]
	}
	c.logf("%s: %s", id, text)
}

// accept checks a NodeTrust update and keeps it if it passes. An unchanged
// update is not checked again; a bad one is counted and ignored, so the
// last good state stays in force.
func (c *Controller) accept(id string, s *nodetrust.Signed) {
	r := c.rec(id)
	if s == nil || s.Payload == r.Payload {
		return
	}
	st, err := nodetrust.Check(c.Pub, s, id, r.Seq, c.now(), 0)
	if err != nil {
		r.BadUpdates++
		if r.LastBad != err.Error() {
			r.LastBad = err.Error()
			c.event(id, r, "ignored NodeTrust update: "+err.Error())
		}
		return
	}
	r.Seq, r.Payload, r.State = st.Seq, s.Payload, st
}

// Reconcile runs one round: read NodeTrust and Nodes, act, save.
func (c *Controller) Reconcile(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	items, err := c.Kube.NodeTrusts(ctx)
	if err != nil {
		return fmt.Errorf("list NodeTrust: %w", err)
	}
	nodes, err := c.Kube.Nodes(ctx)
	if err != nil {
		return fmt.Errorf("list nodes: %w", err)
	}
	for id, s := range items {
		c.accept(id, s)
	}
	byID := map[string]Node{}
	for _, n := range nodes {
		if id := n.InstanceID(); id != "" && !n.ControlPlane() {
			byID[id] = n
		}
	}
	now := c.now()

	// Verifier outage (8.4): every known node's last update is stale at
	// once. No new action; containment already under way goes on.
	known, fresh := 0, 0
	for id := range byID {
		if r := c.recs[id]; r != nil && r.State != nil {
			known++
			if now.Sub(r.State.IssuedAt) <= c.Cfg.MaxAge && r.State.State != "outage" {
				fresh++
			}
		}
	}
	outage := known > 0 && fresh == 0
	// The circuit breaker's fleet: workers with a fresh signed state. Node
	// objects of terminated instances stay in the API (kubeadm has no cloud
	// controller to remove them) and must not dilute the fraction.
	attested := fresh
	if outage != c.outage {
		c.outage = outage
		if outage {
			c.logf("verifier outage: no fresh NodeTrust update for any node; holding all new actions")
		} else {
			c.logf("verifier outage over")
		}
	}

	ids := map[string]bool{}
	for id := range byID {
		ids[id] = true
	}
	for id, r := range c.recs {
		if r.Phase != "" && r.Phase != PhaseReleased {
			ids[id] = true
		}
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)

	c.breaker = false
	var firstErr error
	for _, id := range sorted {
		r := c.rec(id)
		n, hasNode := byID[id]
		stale := r.State != nil && now.Sub(r.State.IssuedAt) > c.Cfg.MaxAge
		spec := Desired(r.State, stale)
		var err error
		switch {
		case r.Phase != "" || (spec.Critical && !outage):
			err = c.critical(ctx, id, r, n, hasNode, spec, attested)
		case outage || !hasNode:
		default:
			err = c.apply(ctx, id, r, n, spec)
		}
		if err != nil {
			c.event(id, r, "error: "+err.Error())
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if err := c.save(byID); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// nodePlan is the list of changes the node needs, and the patch for them.
func nodePlan(n Node, spec Spec) (plan []string, taints []Taint, cordon bool, ann map[string]*string) {
	taints = Merge(n.Taints, spec.Taints)
	if !SameTaints(taints, n.Taints) {
		var ks []string
		for _, t := range spec.Taints {
			ks = append(ks, strings.TrimPrefix(t.Key, Prefix)+":"+t.Effect)
		}
		if len(ks) == 0 {
			ks = []string{"removed"}
		}
		plan = append(plan, "trust taints "+strings.Join(ks, ","))
	}
	cordon = n.Unschedulable
	ann = map[string]*string{}
	switch {
	case spec.Cordon && !n.Unschedulable:
		cordon = true
		v := "nodetrust"
		ann[AnnCordoned] = &v
		plan = append(plan, "cordon")
	case spec.Uncordon && n.Unschedulable && n.Annotations[AnnCordoned] == "nodetrust":
		cordon = false
		ann[AnnCordoned] = nil
		plan = append(plan, "uncordon")
	}
	return plan, taints, cordon, ann
}

// run logs a plan and, unless in dry-run, carries it out with do. The same
// dry-run plan is logged only when it changes.
func (c *Controller) run(id string, r *Record, plan []string, do func() error) error {
	if len(plan) == 0 {
		r.LastPlan = nil
		return nil
	}
	if c.Cfg.DryRun {
		if strings.Join(plan, "|") != strings.Join(r.LastPlan, "|") {
			for _, p := range plan {
				if strings.HasPrefix(p, "(") {
					c.event(id, r, "dry-run: "+p)
				} else {
					c.event(id, r, "dry-run: would "+p)
				}
			}
			r.LastPlan = plan
		}
		return nil
	}
	if err := do(); err != nil {
		return err
	}
	for _, p := range plan {
		c.event(id, r, p)
	}
	return nil
}

// apply brings a node that is not critical to its tier's spec.
func (c *Controller) apply(ctx context.Context, id string, r *Record, n Node, spec Spec) error {
	plan, taints, cordon, ann := nodePlan(n, spec)
	var evict []Pod
	if spec.EvictTagged {
		pods, err := c.Kube.PodsOn(ctx, n.Name)
		if err != nil {
			return err
		}
		for _, p := range pods {
			if p.Labels[LabelSensitive] == "true" {
				evict = append(evict, p)
				plan = append(plan, "evict "+p.Namespace+"/"+p.Name)
			}
		}
	}
	if len(plan) > 0 {
		plan = append([]string{"(" + spec.Reason + ")"}, plan...)
	}
	return c.run(id, r, plan, func() error {
		if err := c.Kube.PatchNode(ctx, n, taints, cordon, ann); err != nil {
			return err
		}
		for _, p := range evict {
			if err := c.Kube.Evict(ctx, p.Namespace, p.Name); err != nil {
				return err
			}
		}
		return nil
	})
}

// approved reports whether an operator approved containment of id
// (the file approve/<id> in the state directory, written by
// "controller approve").
func (c *Controller) approved(id string) bool {
	_, err := os.Stat(filepath.Join(c.StateDir, "approve", id))
	return err == nil
}

// critical runs the critical path (blueprint 8.3) for one instance, as far
// as it can go in this round.
func (c *Controller) critical(ctx context.Context, id string, r *Record, n Node, hasNode bool, spec Spec, workers int) error {
	now := c.now()
	if r.CriticalAt.IsZero() {
		r.CriticalAt, r.Reason, r.DryCritical = now.UTC(), spec.Reason, c.Cfg.DryRun
		c.event(id, r, "critical: "+spec.Reason)
	}
	spec = Spec{Critical: true, Cordon: true, Taints: []Taint{{Key: TaintCritical, Effect: "NoExecute"}}, Reason: r.Reason}
	var plan []string
	var taints []Taint
	var cordon bool
	var ann map[string]*string
	if hasNode && r.Phase != PhaseReleased {
		plan, taints, cordon, ann = nodePlan(n, spec)
		if r.Secrets == nil {
			pods, err := c.Kube.PodsOn(ctx, n.Name)
			if err != nil {
				return err
			}
			r.Secrets = secretsOf(pods)
			if len(r.Secrets) > 0 {
				plan = append(plan, "flag for rotation: "+strings.Join(r.Secrets, ", "))
			}
		}
	}

	// Circuit breaker (8.4): too many critical nodes in the window hold
	// steps 2-5 for an operator; step 1 (cordon, taint) still happens.
	if !r.Approved && c.approved(id) {
		r.Approved = true
		c.event(id, r, "operator approved containment")
	}
	held := false
	if !r.Approved {
		count := 0
		for _, o := range c.recs {
			if !o.CriticalAt.IsZero() && now.Sub(o.CriticalAt) <= c.Cfg.BreakerWindow {
				count++
			}
		}
		if count > c.Cfg.BreakerNodes || (workers > 0 && float64(count) > c.Cfg.BreakerFraction*float64(workers)) {
			held = true
			c.breaker = true
			plan = append(plan, fmt.Sprintf("hold isolation: circuit breaker open (%d critical of %d workers in %s; approve with: controller approve -instance %s)",
				count, workers, c.Cfg.BreakerWindow, id))
		}
	}

	var steps []string
	if !held {
		switch r.Phase {
		case "", PhaseCordoned, PhaseHeld:
			steps = []string{PhaseIsolated, PhaseSnapshot, PhaseReplaced, PhaseReleased}
		case PhaseIsolated:
			steps = []string{PhaseSnapshot, PhaseReplaced, PhaseReleased}
		case PhaseSnapshot:
			steps = []string{PhaseReplaced, PhaseReleased}
		case PhaseReplaced:
			steps = []string{PhaseReleased}
		}
		for _, s := range steps {
			plan = append(plan, stepText[s])
		}
	}

	if c.Cfg.DryRun {
		return c.run(id, r, plan, nil)
	}
	// Step 1.
	if hasNode && r.Phase != PhaseReleased && len(taints) > 0 {
		if err := c.Kube.PatchNode(ctx, n, taints, cordon, ann); err != nil {
			return err
		}
	}
	if r.Phase == "" {
		r.Phase = PhaseCordoned
		c.event(id, r, "cordoned and tainted "+TaintCritical+":NoExecute")
		if len(r.Secrets) > 0 {
			c.event(id, r, "secrets to rotate: "+strings.Join(r.Secrets, ", "))
		}
	}
	if held {
		if r.Phase != PhaseHeld {
			r.Phase = PhaseHeld
			c.event(id, r, plan[len(plan)-1])
		}
		return nil
	}
	// Steps 2-5.
	pid := provider.InstanceID(id)
	for _, s := range steps {
		var err error
		switch s {
		case PhaseIsolated:
			err = c.Cloud.Isolate(ctx, pid)
		case PhaseSnapshot:
			var snaps []provider.SnapshotID
			snaps, err = c.Cloud.Snapshot(ctx, pid, r.Reason)
			for _, x := range snaps {
				r.Snapshots = append(r.Snapshots, string(x))
			}
		case PhaseReplaced:
			err = c.Cloud.Replace(ctx, pid)
		case PhaseReleased:
			if hasNode {
				err = c.Kube.DeleteNode(ctx, n.Name)
			}
		}
		if err != nil {
			return fmt.Errorf("%s: %w", stepText[s], err)
		}
		r.Phase = s
		text := stepText[s]
		if s == PhaseSnapshot {
			text += ": " + strings.Join(r.Snapshots, ", ")
		}
		c.event(id, r, text+" (done in "+c.now().Sub(r.CriticalAt).Round(time.Millisecond).String()+")")
	}
	return nil
}

var stepText = map[string]string{
	PhaseIsolated: "isolate: quarantine security group and NACL deny",
	PhaseSnapshot: "snapshot the EBS volumes",
	PhaseReplaced: "replace: detach from the Auto Scaling group (desired capacity kept)",
	PhaseReleased: "release workloads: delete the Node object",
}

// secretsOf lists the secrets and service accounts the pods use, for
// rotation (blueprint 8.3 step 6).
func secretsOf(pods []Pod) []string {
	set := map[string]bool{}
	for _, p := range pods {
		for _, s := range p.Secrets {
			set[p.Namespace+"/"+s] = true
		}
		if p.ServiceAccount != "" {
			set[p.Namespace+"/serviceaccount:"+p.ServiceAccount] = true
		}
	}
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// NodeStatus is one line of status.json.
type NodeStatus struct {
	InstanceID string   `json:"instance_id"`
	Node       string   `json:"node,omitempty"`
	Tier       string   `json:"tier,omitempty"`
	Score      float64  `json:"score"`
	Critical   bool     `json:"critical"`
	Unattested bool     `json:"unattested"`
	Seq        uint64   `json:"seq"`
	AgeSeconds int      `json:"age_seconds"`
	BadUpdates int      `json:"bad_updates"`
	Phase      string   `json:"phase,omitempty"`
	Snapshots  []string `json:"snapshots,omitempty"`
	Secrets    []string `json:"secrets,omitempty"`
	Recent     []Event  `json:"recent,omitempty"`
}

func (c *Controller) save(byID map[string]Node) error {
	if c.StateDir == "" {
		return nil
	}
	b, err := json.MarshalIndent(c.recs, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFile(filepath.Join(c.StateDir, "state.json"), b); err != nil {
		return err
	}
	st := struct {
		UpdatedAt time.Time    `json:"updated_at"`
		DryRun    bool         `json:"dry_run"`
		Outage    bool         `json:"outage"`
		Breaker   bool         `json:"circuit_breaker_open"`
		Nodes     []NodeStatus `json:"nodes"`
	}{UpdatedAt: c.now().UTC(), DryRun: c.Cfg.DryRun, Outage: c.outage, Breaker: c.breaker}
	ids := make([]string, 0, len(c.recs))
	for id := range c.recs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := c.recs[id]
		ns := NodeStatus{InstanceID: id, Node: byID[id].Name, Seq: r.Seq, BadUpdates: r.BadUpdates, Phase: r.Phase,
			Snapshots: r.Snapshots, Secrets: r.Secrets}
		if s := r.State; s != nil {
			ns.Tier, ns.Score, ns.Critical, ns.Unattested = s.Tier, s.Score, s.Critical, s.Unattested
			ns.AgeSeconds = int(c.now().Sub(s.IssuedAt).Seconds())
		}
		if k := len(r.Events); k > 8 {
			ns.Recent = r.Events[k-8:]
		} else {
			ns.Recent = r.Events
		}
		st.Nodes = append(st.Nodes, ns)
	}
	b, err = json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(c.StateDir, "status.json"), b)
}

func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Approve records an operator's approval to contain id past the circuit
// breaker.
func Approve(stateDir, id string) error {
	// Readable by the service's own (dynamic) user; written by root.
	dir := filepath.Join(stateDir, "approve")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, id), []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o644)
}
