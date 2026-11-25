package verifier

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"nodetrust/pkg/bootpolicy"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/joinref"
	"nodetrust/pkg/manifest"
	"nodetrust/pkg/metrics"
	"nodetrust/pkg/nodetrust"
	"nodetrust/pkg/provider"
	"nodetrust/pkg/trust"
)

// Inventory lists the workers the verifier is responsible for, from the
// cloud control plane.
type Inventory interface {
	Workers(ctx context.Context) ([]Worker, error)
}

// ManifestSource returns the verified, indexed manifest of an AMI. An
// implementation must check the whole signed chain (manifest.VerifyBundle).
type ManifestSource interface {
	Trusted(ctx context.Context, ami string) (*manifest.Trusted, error)
}

// Node states.
const (
	StateRefused      = "refused"       // AMI not allowed, or its manifest does not verify; never enrolled
	StateEnrollFailed = "enroll-failed" // could not enroll (retried every round)
	StateVerified     = "verified"      // the quote verified; the verdict says what it shows
	StateBadEvidence  = "bad-evidence"  // the quote itself does not verify
	StateUnreachable  = "unreachable"   // enrolled, but no valid quote this cycle
	StateOutage       = "outage"        // every enrolled node failed at once: no action (blueprint 8.4)
)

// NodeStatus is the verifier's current view of one worker.
type NodeStatus struct {
	Worker
	State        string    `json:"state"`
	Reason       string    `json:"reason,omitempty"`
	Enrolled     bool      `json:"enrolled"`
	EnrolledAt   time.Time `json:"enrolled_at,omitempty"`
	LastQuote    time.Time `json:"last_quote,omitempty"`
	ResetCount   uint32    `json:"reset_count,omitempty"`
	RestartCount uint32    `json:"restart_count,omitempty"`
	Verdict      *Verdict  `json:"verdict,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`

	// What the verifier remembers about the node across cycles (enrolled
	// nodes only, step 4.4). Tier, Critical and Unattested are what the
	// trust controller acts on.
	Tier             string             `json:"tier,omitempty"`
	Score            float64            `json:"score"`
	Components       map[string]float64 `json:"components,omitempty"`
	Mismatched       map[string]int     `json:"mismatched,omitempty"`
	Files            []trust.File       `json:"files,omitempty"` // sticky mismatched files (first 20)
	Critical         bool               `json:"critical"`
	CriticalAt       time.Time          `json:"critical_at,omitempty"`
	Findings         []trust.Finding    `json:"findings,omitempty"`
	Unattested       bool               `json:"unattested"`
	UnattestedReason string             `json:"unattested_reason,omitempty"`
	Reboots          int                `json:"reboots,omitempty"`
	FailStreak       int                `json:"fail_streak,omitempty"`
	Cycles           int                `json:"cycles"`
	Drops            []trust.Drop       `json:"drops,omitempty"`  // recent score drops with their drift class
	Recent           []Event            `json:"recent,omitempty"` // last few events
	AgentVersion     string             `json:"agent_version,omitempty"`
	IMAEntries       int                `json:"ima_entries,omitempty"` // verified entries in this boot
	Interval         float64            `json:"interval_s,omitempty"`  // challenge interval now (blueprint 6.2)
	NextDue          time.Time          `json:"next_due,omitempty"`
	Published        uint64             `json:"published_seq,omitempty"` // last NodeTrust update that the API server took
	PublishError     string             `json:"publish_error,omitempty"`
}

// TrustPublisher writes signed NodeTrust updates (pkg/nodetrust).
type TrustPublisher interface {
	Publish(ctx context.Context, st *nodetrust.State) error
	Remove(ctx context.Context, instanceID string) error
}

// Probes say what each challenge includes besides the quote (blueprint 6.2
// step 2). All are on in service; tests without a real IMA turn them off.
type Probes struct {
	Canary bool
	Sweep  bool
	Mounts bool
}

// AllProbes turns every probe on.
var AllProbes = Probes{Canary: true, Sweep: true, Mounts: true}

// Forced-read sweep sets (blueprint 10.2). The critical set is opened before
// every quote; the full set every FullSweepEvery cycles and in the first
// cycle of a boot. Opening a file that has not changed costs IMA nothing,
// so after the first full sweep of a boot later ones are cheap. Kernel
// modules and firmware are left out: they are measured when the kernel
// loads them, and modules are locked after boot.
var (
	CriticalSweep = []string{
		"/usr/bin/kubelet", "/usr/bin/containerd", "/usr/bin/containerd-shim-runc-v2",
		"/usr/sbin/runc", "/usr/bin/runc", "/usr/local/bin", "/usr/bin/falco", "/usr/sbin/sshd",
		"/etc/nodetrust", "/boot",
	}
	FullSweep = []string{
		"/usr/bin", "/usr/sbin", "/usr/local", "/usr/libexec", "/opt/cni/bin", "/etc",
		"/var/lib/kubelet/config.yaml", "/boot",
		"/usr/lib/systemd", "/usr/lib/x86_64-linux-gnu", "/usr/lib/python3", "/usr/lib/sudo",
		"/usr/lib/openssh", "/usr/lib/apt", "/usr/lib/dpkg", "/usr/lib/udev",
	}
)

// Sweep timing.
const (
	FullSweepEvery  = 10
	criticalSweepMS = 5000
	fullSweepMS     = 20000
)

// Daemon is the verifier service (blueprint Phase 4, step 4.2): each round
// it lists the workers, enrolls new ones whose AMI is allowed and whose
// manifest verifies, and checks a fresh quote from every enrolled one.
type Daemon struct {
	Inventory     Inventory
	Endorsement   provider.EndorsementProvider
	Manifests     ManifestSource
	AllowedAMIs   map[string]bool
	RuntimePolicy *imapolicy.Policy
	BootPolicy    *bootpolicy.Policy // nil skips boot checks (simulator tests only)
	JoinRef       *joinref.Reference // join-time files (blueprint 10.4); nil leaves them to the runtime policy
	Publisher     TrustPublisher     // signed NodeTrust updates in the cluster (blueprint 8.1); nil publishes nothing
	Metrics       *metrics.Registry  // counters and histogram (NewMetrics); nil records none
	Cert          tls.Certificate    // verifier client certificate for the agents
	StateDir      string             // enrolled/<id>.json and status.json
	Interval      time.Duration      // challenge interval for a healthy node; shorter for others (IntervalFor)
	Probes        Probes
	Parallel      int
	Log           *log.Logger
	Now           func() time.Time
	// Dial makes an agent client; nil means NewClient(addr, Cert).
	Dial func(addr string) *Client

	mu       sync.Mutex
	nodes    map[string]*NodeStatus
	enrolled map[string]*Enrolled
	tracks   map[string]*Track
	due      map[string]time.Time
	busy     map[string]bool
	hinted   map[string]time.Time
	last     map[string]time.Time // start of the node's last cycle
	hints    map[string]context.CancelFunc
	cycles   int // challenges since the last status log line
	statusMu sync.Mutex
	votes    *joinref.Consensus
}

func (d *Daemon) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

func (d *Daemon) logf(f string, a ...any) {
	if d.Log != nil {
		d.Log.Printf(f, a...)
	}
}

func (d *Daemon) dial(addr string) *Client {
	if d.Dial != nil {
		return d.Dial(addr)
	}
	return NewClient(addr, d.Cert)
}

// Load reads enrolled records from StateDir, so a restart keeps them.
func (d *Daemon) Load() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodes, d.enrolled, d.tracks = map[string]*NodeStatus{}, map[string]*Enrolled{}, map[string]*Track{}
	d.due, d.busy, d.hinted, d.last, d.hints = map[string]time.Time{}, map[string]bool{}, map[string]time.Time{}, map[string]time.Time{}, map[string]context.CancelFunc{}
	d.votes = joinref.NewConsensus()
	if d.StateDir == "" {
		return nil
	}
	if err := os.MkdirAll(d.StateDir, 0o700); err != nil {
		return err
	}
	v, err := joinref.LoadConsensus(filepath.Join(d.StateDir, "consensus.json"))
	if err != nil {
		return err
	}
	d.votes = v
	tdir := filepath.Join(d.StateDir, "track")
	if err := os.MkdirAll(tdir, 0o700); err != nil {
		return err
	}
	tents, err := os.ReadDir(tdir)
	if err != nil {
		return err
	}
	for _, de := range tents {
		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		t := &Track{}
		if err := readJSONFile(filepath.Join(tdir, de.Name()), t); err != nil {
			return err
		}
		d.tracks[t.InstanceID] = t
	}
	dir := filepath.Join(d.StateDir, "enrolled")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range ents {
		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		var e Enrolled
		if err := readJSONFile(filepath.Join(dir, de.Name()), &e); err != nil {
			return err
		}
		d.enrolled[e.InstanceID] = &e
	}
	return nil
}

// Status returns a copy of every node's status, sorted by instance ID.
func (d *Daemon) Status() []NodeStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]NodeStatus, 0, len(d.nodes))
	for _, n := range d.nodes {
		out = append(out, *n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].InstanceID < out[j].InstanceID })
	return out
}

// Round runs one pass over the inventory.
func (d *Daemon) Round(ctx context.Context) error {
	if d.nodes == nil {
		if err := d.Load(); err != nil {
			return err
		}
	}
	ws, err := d.Inventory.Workers(ctx)
	if err != nil {
		return fmt.Errorf("inventory: %w", err)
	}
	seen := map[string]bool{}
	for _, w := range ws {
		seen[w.InstanceID] = true
	}
	d.forget(seen)

	par := d.Parallel
	if par < 1 {
		par = 4
	}
	sem := make(chan struct{}, par)
	var wg sync.WaitGroup
	outs := make([]*outcome, len(ws))
	for i, w := range ws {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, w Worker) {
			defer wg.Done()
			defer func() { <-sem }()
			outs[i] = d.visit(ctx, w)
		}(i, w)
	}
	wg.Wait()

	for _, o := range outs {
		if o != nil {
			d.record(ctx, o)
		}
	}
	return d.writeStatus()
}

// record folds a visit into the node's state, unless it looks like a
// verifier or network outage. Blueprint 8.4: an outage is not node failure;
// only a node that goes silent while others answer is counted. So a failed
// cycle counts only if at least one other enrolled node's agent still
// accepts a connection.
func (d *Daemon) record(ctx context.Context, o *outcome) {
	last := o.obs[len(o.obs)-1]
	if last.State == StateUnreachable && !d.othersReachable(ctx, o.w.InstanceID) {
		d.set(o.w, StateOutage, "no other enrolled node is reachable either, not counted: "+last.Reason, nil)
		d.failure(o.w.InstanceID, "outage")
		return
	}
	d.observe(o)
}

// othersReachable dials the agents of the other enrolled nodes.
func (d *Daemon) othersReachable(ctx context.Context, except string) bool {
	d.mu.Lock()
	var addrs []string
	for id := range d.enrolled {
		if n := d.nodes[id]; id != except && n != nil && n.Addr != "" {
			addrs = append(addrs, n.Addr)
		}
	}
	d.mu.Unlock()
	for _, a := range addrs {
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		c, err := (&net.Dialer{}).DialContext(dctx, "tcp", a)
		cancel()
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

// outcome is what a visit found for an enrolled node: one observation per
// cycle (two when the first failed and was retried).
type outcome struct {
	full bool // the full sweep set was asked for
	w    Worker
	obs  []Observation
	q    *QuoteResult
	v    *Verdict
}

// forget drops nodes the inventory no longer lists (terminated instances).
func (d *Daemon) forget(seen map[string]bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id := range d.enrolled {
		if !seen[id] {
			delete(d.enrolled, id)
			if d.StateDir != "" {
				os.Remove(filepath.Join(d.StateDir, "enrolled", id+".json"))
			}
			d.logf("%s: gone from the inventory, enrollment dropped", id)
		}
	}
	for _, id := range d.goneTracks(seen) {
		d.votes.Forget(id)
		if d.Publisher != nil {
			go func(id string) {
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				if err := d.Publisher.Remove(ctx, id); err != nil {
					d.logf("%s: removing NodeTrust: %v", id, err)
				}
			}(id)
		}
	}
	for id := range d.tracks {
		if !seen[id] {
			delete(d.tracks, id)
			if d.StateDir != "" {
				os.Remove(filepath.Join(d.StateDir, "track", id+".json"))
			}
		}
	}
	for id := range d.nodes {
		if !seen[id] {
			delete(d.nodes, id)
		}
	}
}

func (d *Daemon) set(w Worker, state, reason string, mod func(*NodeStatus)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.nodes[w.InstanceID]
	if n == nil {
		n = &NodeStatus{}
		d.nodes[w.InstanceID] = n
	}
	prev := n.State
	n.Worker, n.State, n.Reason, n.UpdatedAt = w, state, reason, d.now().UTC()
	if e := d.enrolled[w.InstanceID]; e != nil {
		n.Enrolled, n.EnrolledAt = true, e.EnrolledAt
	} else {
		n.Enrolled = false
	}
	if mod != nil {
		mod(n)
	}
	if prev != state {
		d.logf("%s: %s -> %s %s", w.InstanceID, orNone(prev), state, reason)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(new)"
	}
	return s
}

// Timeouts: enrollment may take a while (key creation in the TPM); a
// challenge must be answered within cycleTimeout (blueprint 6.3), and a
// failed cycle is retried once after retryDelay.
const (
	enrollTimeout = 60 * time.Second
	cycleTimeout  = 10 * time.Second
	retryDelay    = 2 * time.Second
)

// visit checks one worker. It returns nil for a node that is not enrolled
// (refused or enrollment failed; those are recorded directly).
func (d *Daemon) visit(ctx context.Context, w Worker) *outcome {
	ectx, cancel := context.WithTimeout(ctx, enrollTimeout)
	defer cancel()
	// The AMI comes from EC2, not from the node, so the allow-list cannot be
	// talked around by the node.
	if !d.AllowedAMIs[w.AMI] {
		d.set(w, StateRefused, "AMI "+w.AMI+" is not on the allow-list", nil)
		return nil
	}
	tr, err := d.Manifests.Trusted(ectx, w.AMI)
	if err != nil {
		d.set(w, StateRefused, "manifest for "+w.AMI+": "+err.Error(), nil)
		return nil
	}
	d.mu.Lock()
	e := d.enrolled[w.InstanceID]
	d.mu.Unlock()
	if e == nil {
		if e, err = d.enroll(ectx, w); err != nil {
			d.set(w, StateEnrollFailed, err.Error(), nil)
			return nil
		}
	}
	out := &outcome{w: w}
	d.mu.Lock()
	var st ReplayState
	cycles, pending := 0, false
	if t := d.tracks[w.InstanceID]; t != nil {
		st, cycles, pending = t.Replay, t.Cycles, t.SweepPending
	}
	d.mu.Unlock()
	opt := QuoteOptions{State: st, Canary: d.Probes.Canary, Mounts: d.Probes.Mounts}
	if d.Probes.Sweep {
		opt.Sweep, opt.SweepMS = CriticalSweep, criticalSweepMS
		if !st.Valid || cycles%FullSweepEvery == 0 || pending {
			opt.Sweep, opt.SweepMS = FullSweep, fullSweepMS
			out.full = true
		}
	}
	timeout := cycleTimeout + time.Duration(opt.SweepMS)*time.Millisecond
	start := d.now()
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return out
			case <-time.After(retryDelay):
			}
		}
		cctx, ccancel := context.WithTimeout(ctx, timeout)
		q, err := d.dial(w.Addr).Quote(cctx, e, opt)
		ccancel()
		at := d.now()
		var ee *EvidenceError
		switch {
		case errors.As(err, &ee):
			out.obs = append(out.obs, Observation{At: at, State: StateBadEvidence, Reason: err.Error()})
			return out
		case err != nil:
			out.obs = append(out.obs, Observation{At: at, State: StateUnreachable, Reason: err.Error()})
			continue
		}
		jc := d.joinCheck(w, true)
		v := Judge(q, w, tr, d.RuntimePolicy, d.BootPolicy, jc)
		d.duration(w.InstanceID, d.now().Sub(start).Seconds())
		out.q, out.v = q, v
		next := q.Next
		out.obs = append(out.obs, Observation{At: at, State: StateVerified, Quote: q.Quote, Verdict: v, Next: &next,
			Still: d.stillFunc(w, tr)})
		return out
	}
	return out
}

// stillFunc makes the Observation.Still check for a node. Track.Observe
// calls it while d.mu is held, so everything that needs d.mu (the join
// check) is prepared here, before.
func (d *Daemon) stillFunc(w Worker, tr *manifest.Trusted) func(trust.File) bool {
	jc := d.joinCheck(w, false)
	return func(f trust.File) bool { return stillBad(f, tr, d.RuntimePolicy, jc) }
}

// stillBad re-classifies a remembered file under the manifest and policy in
// force now, so a corrected manifest clears it (blueprint 7.1).
func stillBad(f trust.File, tr *manifest.Trusted, rt *imapolicy.Policy, jc JoinCheck) bool {
	if jc != nil {
		if c, ok := jc(f.Path, f.SHA256); ok {
			return c == imapolicy.Mismatch
		}
	}
	r := imapolicy.Classify([]imapolicy.Measurement{{Path: f.Path, SHA256: f.SHA256}}, tr.Index, rt)
	c := r.Items[0].Class
	return c == imapolicy.Mismatch || c == imapolicy.Unknown
}

// recentEvents is how much history status.json shows per node; the full
// history (50 events) is in track/<id>.json.
const recentEvents = 8

// observe folds a visit's cycles into the node's track, saves the track and
// updates the node's status.
func (d *Daemon) observe(o *outcome) {
	w := o.w
	d.mu.Lock()
	t := d.tracks[w.InstanceID]
	if t == nil {
		t = NewTrack(w.InstanceID)
		d.tracks[w.InstanceID] = t
	}
	var events []Event
	for _, ob := range o.obs {
		events = append(events, t.Observe(ob)...)
	}
	if o.q != nil && o.q.Sweep != nil && o.full {
		t.SweepPending = o.q.Sweep.Partial
	}
	if d.Publisher != nil {
		t.PublishSeq++
	}
	snap := *t
	files := t.SortedFiles(maxFilesListed)
	d.mu.Unlock()

	for _, ev := range events {
		d.logf("%s: %s %s (score %g)", w.InstanceID, ev.Kind, ev.Detail, ev.Score)
	}
	d.count(w.InstanceID, events)
	for _, ob := range o.obs {
		switch ob.State {
		case StateUnreachable:
			d.failure(w.InstanceID, "unreachable")
		case StateBadEvidence:
			d.failure(w.InstanceID, "bad-evidence")
		}
	}
	if d.StateDir != "" {
		if err := writeJSONFile(filepath.Join(d.StateDir, "track", w.InstanceID+".json"), &snap); err != nil {
			d.logf("%s: saving track: %v", w.InstanceID, err)
		}
	}
	last := o.obs[len(o.obs)-1]
	var pubErr error
	if d.Publisher != nil {
		st := trustState(&snap, w, files, last.State, d.now())
		pctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		pubErr = d.Publisher.Publish(pctx, st)
		cancel()
		if pubErr != nil {
			d.logf("%s: NodeTrust update %d: %v", w.InstanceID, st.Seq, pubErr)
		}
	}
	reason := last.Reason
	if last.State == StateVerified && o.v != nil {
		reason = o.v.Summary()
	}
	d.set(w, last.State, reason, func(n *NodeStatus) {
		if o.q != nil {
			n.LastQuote = last.At.UTC()
			n.ResetCount, n.RestartCount = o.q.Quote.ResetCount, o.q.Quote.RestartCount
		}
		if o.v != nil {
			v := *o.v
			v.trim()
			n.Verdict = &v
		}
		n.Tier, n.Score, n.Components, n.Mismatched, n.Files = snap.Tier, snap.Score, snap.Components, snap.Mismatched, files
		n.Critical, n.CriticalAt, n.Findings = snap.Critical, snap.CriticalAt, snap.Findings
		n.Unattested, n.UnattestedReason = snap.Unattested, snap.UnattestedReason
		n.Reboots, n.FailStreak, n.Cycles = snap.Reboots, snap.FailStreak, snap.Cycles
		n.IMAEntries = snap.Replay.Entries
		if d.Publisher != nil {
			if pubErr == nil {
				n.Published, n.PublishError = snap.PublishSeq, ""
			} else {
				n.PublishError = pubErr.Error()
			}
		}
		if o.q != nil {
			n.AgentVersion = o.q.AgentVersion
		}
		dr := snap.Drops
		if len(dr) > recentEvents {
			dr = dr[len(dr)-recentEvents:]
		}
		n.Drops = append([]trust.Drop(nil), dr...)
		h := snap.History
		if len(h) > recentEvents {
			h = h[len(h)-recentEvents:]
		}
		n.Recent = append([]Event(nil), h...)
	})
}

func (d *Daemon) enroll(ctx context.Context, w Worker) (*Enrolled, error) {
	// The EK comes from the cloud API for the instance ID the cloud lists,
	// never from the agent.
	ek, err := d.Endorsement.EKPublic(ctx, provider.InstanceID(w.InstanceID), provider.EKRSA2048)
	if err != nil {
		return nil, fmt.Errorf("EK from the cloud: %w", err)
	}
	e, err := d.dial(w.Addr).Enroll(ctx, w.InstanceID, ek)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.enrolled[w.InstanceID] = e
	d.mu.Unlock()
	if d.StateDir != "" {
		if err := writeJSONFile(filepath.Join(d.StateDir, "enrolled", w.InstanceID+".json"), e); err != nil {
			return nil, err
		}
	}
	d.logf("%s: enrolled (EK from the cloud, AK %s…)", w.InstanceID, e.AKName[:16])
	return e, nil
}

func (d *Daemon) writeStatus() error {
	if d.StateDir == "" {
		return nil
	}
	d.statusMu.Lock()
	defer d.statusMu.Unlock()
	return writeJSONFile(filepath.Join(d.StateDir, "status.json"), struct {
		UpdatedAt time.Time    `json:"updated_at"`
		Nodes     []NodeStatus `json:"nodes"`
	}{d.now().UTC(), d.Status()})
}

// Scheduling (blueprint 6.2, 10.5).
const (
	inventoryEvery = 30 * time.Second
	hintGap        = 5 * time.Second // at most one hinted challenge per node this often
	recentChange   = 10 * time.Minute
	minInterval    = 5 * time.Second
	statusLogEvery = time.Minute
)

func (d *Daemon) base() time.Duration {
	if d.Interval <= 0 {
		return 60 * time.Second
	}
	return d.Interval
}

// IntervalFor is how often a node is challenged: the base interval when
// healthy, half of it at warning, a quarter when degraded, unattested,
// critical, not yet verified, or changed (rebooted or lost score) in the
// last 10 minutes. The caller must not hold d.mu.
func (d *Daemon) IntervalFor(id string) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.intervalFor(id)
}

func (d *Daemon) intervalFor(id string) time.Duration {
	b := d.base()
	t := d.tracks[id]
	var iv time.Duration
	switch {
	case t == nil || !t.Seen || t.Critical || t.Unattested || d.now().Sub(t.LastChange) < recentChange:
		iv = b / 4
	case t.Tier == trust.Degraded || t.Tier == trust.Untrusted:
		iv = b / 4
	case t.Tier == trust.Warning:
		iv = b / 2
	default:
		iv = b
	}
	return max(iv, minInterval)
}

// Run challenges every node on its own schedule until ctx ends. The
// inventory is refreshed every 30 s; each enrolled node also has a hint
// watcher that asks for a challenge at once when its IMA log grows.
func (d *Daemon) Run(ctx context.Context) error {
	if d.nodes == nil {
		if err := d.Load(); err != nil {
			return err
		}
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	var workers []Worker
	var lastInv, lastLog time.Time
	for {
		now := d.now()
		if now.Sub(lastInv) >= inventoryEvery {
			ws, err := d.Inventory.Workers(ctx)
			if err != nil {
				d.logf("inventory: %v", err)
			} else {
				seen := map[string]bool{}
				for _, w := range ws {
					seen[w.InstanceID] = true
				}
				d.forget(seen)
				workers, lastInv = ws, now
			}
		}
		d.syncHints(ctx, workers)
		for _, w := range workers {
			if d.claim(w.InstanceID, now) {
				go d.cycle(ctx, w)
			}
		}
		if now.Sub(lastLog) >= statusLogEvery {
			d.logStatus()
			lastLog = now
		}
		select {
		case <-ctx.Done():
			d.mu.Lock()
			for _, c := range d.hints {
				c()
			}
			d.mu.Unlock()
			return ctx.Err()
		case <-tick.C:
		}
	}
}

// claim marks a node busy if it is due: its interval has passed, or a hint
// arrived after its last cycle and at least hintGap after it started.
func (d *Daemon) claim(id string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.busy[id] {
		return false
	}
	hinted := d.hinted[id].After(d.last[id]) && now.Sub(d.last[id]) >= hintGap
	if !hinted && now.Before(d.due[id]) {
		return false
	}
	d.busy[id], d.last[id] = true, now
	return true
}

// cycle is one challenge of one node, then its next due time.
func (d *Daemon) cycle(ctx context.Context, w Worker) {
	if o := d.visit(ctx, w); o != nil {
		d.record(ctx, o)
	}
	d.mu.Lock()
	iv := d.intervalFor(w.InstanceID)
	next := d.now().Add(iv)
	d.busy[w.InstanceID], d.due[w.InstanceID] = false, next
	d.cycles++
	if n := d.nodes[w.InstanceID]; n != nil {
		n.NextDue, n.Interval = next.UTC(), iv.Seconds()
	}
	d.mu.Unlock()
	if err := d.writeStatus(); err != nil {
		d.logf("status: %v", err)
	}
}

// syncHints starts a hint watcher for every enrolled node and stops the
// ones for nodes that are gone.
func (d *Daemon) syncHints(ctx context.Context, ws []Worker) {
	d.mu.Lock()
	defer d.mu.Unlock()
	want := map[string]Worker{}
	for _, w := range ws {
		if d.enrolled[w.InstanceID] != nil {
			want[w.InstanceID] = w
		}
	}
	for id, c := range d.hints {
		if _, ok := want[id]; !ok {
			c()
			delete(d.hints, id)
		}
	}
	for id, w := range want {
		if d.hints[id] == nil {
			hctx, c := context.WithCancel(ctx)
			d.hints[id] = c
			go d.watchHints(hctx, w)
		}
	}
}

// watchHints long-polls the agent for new IMA measurements. Hints are
// advisory (blueprint 10.5): errors only slow the watcher down.
func (d *Daemon) watchHints(ctx context.Context, w Worker) {
	c := d.dial(w.Addr)
	for ctx.Err() == nil {
		d.mu.Lock()
		var count uint64
		valid := false
		if t := d.tracks[w.InstanceID]; t != nil && t.Replay.Valid {
			count, valid = t.Replay.Read, true
		}
		d.mu.Unlock()
		if !valid {
			sleep(ctx, 10*time.Second)
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, 40*time.Second)
		n, err := c.Hint(hctx, count)
		cancel()
		switch {
		case err != nil:
			sleep(ctx, 10*time.Second)
		case n > count:
			d.mu.Lock()
			d.hinted[w.InstanceID] = d.now()
			d.mu.Unlock()
			sleep(ctx, hintGap) // let the challenge run and move the count on
		}
	}
}

func sleep(ctx context.Context, t time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(t):
	}
}

// logStatus writes one line with the nodes per tier.
func (d *Daemon) logStatus() {
	counts := map[string]int{}
	for _, n := range d.Status() {
		k := n.State
		switch {
		case n.Critical:
			k = "critical"
		case n.Unattested && n.Enrolled:
			k = "unattested"
		case n.Tier != "":
			k = n.Tier
		}
		counts[k]++
	}
	d.mu.Lock()
	c := d.cycles
	d.cycles = 0
	d.mu.Unlock()
	d.logf("nodes: %v (%d challenges in the last minute)", counts, c)
}

func readJSONFile(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// writeJSONFile writes atomically (temp file and rename), mode 0600.
func writeJSONFile(p string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// goneTracks lists tracked nodes the inventory no longer has. The caller
// holds d.mu.
func (d *Daemon) goneTracks(seen map[string]bool) []string {
	var out []string
	for id := range d.tracks {
		if !seen[id] {
			out = append(out, id)
		}
	}
	return out
}

// joinCheck checks join-time files for one node (blueprint 10.4): a file
// with a template in the join reference must have the hash rendered for this
// node; a file under a consensus pattern must have the hash the fleet
// accepts for it on this AMI. With record, the node's hash is counted as a
// vote first, unless the node is critical (a compromised node does not
// vote). It returns nil when there is no join reference.
func (d *Daemon) joinCheck(w Worker, record bool) JoinCheck {
	if d.JoinRef == nil {
		return nil
	}
	host, _, _ := net.SplitHostPort(w.Addr)
	expected := d.JoinRef.Expected(joinref.Node{InstanceID: w.InstanceID, Zone: w.Zone, Address: host})
	d.mu.Lock()
	t := d.tracks[w.InstanceID]
	voter := record && (t == nil || !t.Critical)
	d.mu.Unlock()
	return func(p, sha string) (string, bool) {
		covered := d.JoinRef.InConsensus(p)
		if _, ok := expected[p]; ok {
			covered = true
		}
		if sha == "" { // a measurement violation (read while being written)
			if covered {
				return imapolicy.Violation, true
			}
			return "", false
		}
		if want, ok := expected[p]; ok {
			for _, h := range want {
				if sha == h {
					return imapolicy.Join, true
				}
			}
			return imapolicy.Mismatch, true
		}
		if !d.JoinRef.InConsensus(p) {
			return "", false
		}
		if voter {
			d.votes.Observe(w.AMI, p, sha, w.InstanceID, d.now())
			if d.StateDir != "" {
				if err := d.votes.Save(filepath.Join(d.StateDir, "consensus.json")); err != nil {
					d.logf("consensus: %v", err)
				}
			}
		}
		if acc, _, ok := d.votes.Accepted(w.AMI, p); ok && acc == sha {
			return imapolicy.Join, true
		}
		return imapolicy.Mismatch, true
	}
}

// trustState is what the verifier publishes about a node (blueprint 8.1).
func trustState(t *Track, w Worker, files []trust.File, state string, now time.Time) *nodetrust.State {
	drops := t.Drops
	if len(drops) > recentEvents {
		drops = drops[len(drops)-recentEvents:]
	}
	return &nodetrust.State{
		InstanceID: w.InstanceID, AMI: w.AMI, Seq: t.PublishSeq, IssuedAt: now.UTC(),
		Tier: t.Tier, Score: t.Score, Components: t.Components,
		Critical: t.Critical, Findings: t.Findings,
		Unattested: t.Unattested, UnattestedReason: t.UnattestedReason,
		Files: files, Drift: drops, LastAttestation: t.LastQuote,
		ResetCount: t.ResetCount, Reboots: t.Reboots, State: state,
	}
}
