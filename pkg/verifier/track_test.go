package verifier

import (
	"strings"
	"testing"
	"time"

	"nodetrust/pkg/attest"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/trust"
)

var t0 = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

func q(reset, restart uint32, clock uint64) *attest.QuoteInfo {
	return &attest.QuoteInfo{ResetCount: reset, RestartCount: restart, Clock: clock, FirmwareVersion: 7}
}

// verdict builds a verdict from classified items, like Judge does.
func verdict(items ...imapolicy.Item) *Verdict {
	v := &Verdict{IMA: map[string]int{}, Boot: "pass"}
	v.Critical, v.Files = trust.Assess(items)
	v.Clean = len(v.Critical) == 0 && len(v.Files) == 0
	return v
}

func it(p, class string) imapolicy.Item {
	return imapolicy.Item{Measurement: imapolicy.Measurement{Path: p, SHA256: "bad"}, Class: class}
}

// sim drives a track one cycle at a time, 60 s apart.
type sim struct {
	t     *testing.T
	tr    *Track
	n     int
	reset uint32
	still func(trust.File) bool
	step  time.Duration // between cycles; a minute when zero
}

func newSim(t *testing.T) *sim { return &sim{t: t, tr: NewTrack("i-1"), reset: 5} }

func (s *sim) at() time.Time {
	if s.step == 0 {
		return t0.Add(time.Duration(s.n) * time.Minute)
	}
	return t0.Add(time.Duration(s.n) * s.step)
}

func (s *sim) ok(items ...imapolicy.Item) []string {
	s.n++
	ev := s.tr.Observe(Observation{At: s.at(), State: StateVerified, Quote: q(s.reset, 0, uint64(s.n)*60000),
		Verdict: verdict(items...), Still: s.still})
	return kinds(ev)
}

func (s *sim) fail(state string) []string {
	s.n++
	return kinds(s.tr.Observe(Observation{At: s.at(), State: state, Reason: "r"}))
}

func kinds(ev []Event) []string {
	var k []string
	for _, e := range ev {
		k = append(k, e.Kind)
	}
	return k
}

func (s *sim) want(tier string, score float64, critical bool) {
	s.t.Helper()
	if s.tr.Tier != tier || s.tr.Score != score || s.tr.Critical != critical {
		s.t.Fatalf("cycle %d: %s %g critical=%t, want %s %g critical=%t; history %+v",
			s.n, s.tr.Tier, s.tr.Score, s.tr.Critical, tier, score, critical, s.tr.History)
	}
}

func has(k []string, want string) bool {
	return strings.Contains(" "+strings.Join(k, " ")+" ", " "+want+" ")
}

func TestTrackClean(t *testing.T) {
	s := newSim(t)
	if !s.tr.Unattested {
		t.Fatal("a new node must start unattested")
	}
	for i := 0; i < 5; i++ {
		if k := s.ok(); len(k) != 0 {
			t.Fatalf("clean cycle added events %v", k)
		}
	}
	s.want(trust.Healthy, 100, false)
	if s.tr.Unattested {
		t.Fatal("still unattested after verified quotes")
	}
}

func TestTrackA8IsolatedWarning(t *testing.T) {
	s := newSim(t)
	s.ok()
	k := s.ok(it("/usr/bin/ls", imapolicy.Mismatch))
	if !has(k, "drift-isolated") || !has(k, "tier") {
		t.Fatalf("events %v", k)
	}
	s.want(trust.Warning, 90, false)
	// The file is put back: IMA logs a matching entry, the mismatch stays.
	s.ok(it("/usr/bin/ls", imapolicy.Match))
	s.want(trust.Warning, 90, false)
}

func TestTrackA10SuddenDegraded(t *testing.T) {
	s := newSim(t)
	s.ok()
	k := s.ok(it("/var/lib/kubelet/config.yaml", imapolicy.Mismatch), it("/etc/containerd/config.toml", imapolicy.Mismatch))
	if !has(k, "drift-sudden") {
		t.Fatalf("events %v", k)
	}
	s.want(trust.Degraded, 72.5, false)
}

func TestTrackA11GradualDrift(t *testing.T) {
	s := newSim(t)
	s.ok()
	files := []string{"/etc/ssh/sshd_config", "/etc/sudoers", "/etc/cron.d/e2scrub_all", "/etc/systemd/system/x.service"}
	want := []string{"drift-isolated", "drift-unclassified", "drift-gradual", "drift-gradual"}
	var seen []imapolicy.Item
	for i, f := range files {
		for j := 0; j < 4; j++ { // four quiet cycles between edits: one edit every 5 cycles
			s.ok(seen...)
		}
		seen = append(seen, it(f, imapolicy.Mismatch))
		if k := s.ok(seen...); !has(k, want[i]) {
			t.Fatalf("edit %d: events %v, want %s", i+1, k, want[i])
		}
	}
	s.want(trust.Warning, 80, false)
}

// A11 again with the interval a changed node gets (15 s): 20 cycles
// between edits. The drift window is in time, so the third edit is still
// gradual.
func TestTrackA11At15Seconds(t *testing.T) {
	s := newSim(t)
	s.step = 15 * time.Second
	s.ok()
	files := []string{"/etc/ssh/sshd_config", "/etc/sudoers", "/etc/cron.d/e2scrub_all", "/etc/systemd/system/x.service"}
	want := []string{"drift-isolated", "drift-unclassified", "drift-gradual", "drift-gradual"}
	var seen []imapolicy.Item
	for i, f := range files {
		for j := 0; j < 19; j++ {
			s.ok(seen...)
		}
		seen = append(seen, it(f, imapolicy.Mismatch))
		if k := s.ok(seen...); !has(k, want[i]) {
			t.Fatalf("edit %d: events %v, want %s", i+1, k, want[i])
		}
	}
	s.want(trust.Warning, 80, false)
}

func TestTrackStickyAcrossReboot(t *testing.T) {
	s := newSim(t)
	s.ok()
	s.ok(it("/usr/local/bin/evil", imapolicy.Unknown))
	s.want(trust.Warning, 90, false)
	// Reboot: two failed cycles, then a clean quote from the new boot.
	s.fail(StateUnreachable)
	if k := s.fail(StateUnreachable); !has(k, "unattested") {
		t.Fatalf("two failed cycles: %v", k)
	}
	s.reset++
	k := s.ok()
	if !has(k, "reboot") || !has(k, "reachable") || has(k, "critical") {
		t.Fatalf("after reboot: %v", k)
	}
	s.want(trust.Warning, 90, false) // a reboot does not clear the mismatch
	if s.tr.Unattested || s.tr.Reboots != 1 {
		t.Fatalf("unattested=%t reboots=%d", s.tr.Unattested, s.tr.Reboots)
	}
}

func TestTrackCorrectedManifest(t *testing.T) {
	s := newSim(t)
	s.ok()
	s.ok(it("/usr/bin/ls", imapolicy.Mismatch))
	s.want(trust.Warning, 90, false)
	// A corrected manifest now covers the file: the score recovers at once,
	// the tier only after 3 cycles at the better score (blueprint 8.2).
	s.still = func(trust.File) bool { return false }
	if k := s.ok(); !has(k, "cleared") {
		t.Fatalf("events %v", k)
	}
	s.want(trust.Warning, 100, false)
	s.ok()
	s.want(trust.Warning, 100, false)
	if k := s.ok(); !has(k, "tier") {
		t.Fatalf("events %v", k)
	}
	s.want(trust.Healthy, 100, false)
}

func TestTrackCriticalIsSticky(t *testing.T) {
	s := newSim(t)
	s.ok()
	k := s.ok(it("/usr/bin/kubelet", imapolicy.Mismatch))
	if !has(k, "critical") {
		t.Fatalf("events %v", k)
	}
	s.want(trust.Healthy, 100, true) // critical skips the score
	s.reset++
	s.ok()
	s.ok()
	s.want(trust.Healthy, 100, true)
	if s.tr.Findings[0].Type != trust.CriticalBinary {
		t.Fatalf("%+v", s.tr.Findings)
	}
}

func TestTrackScoreBelow50IsCritical(t *testing.T) {
	s := newSim(t)
	s.ok()
	s.ok(it("/usr/bin/a", imapolicy.Mismatch), it("/usr/bin/b", imapolicy.Mismatch), it("/usr/bin/c", imapolicy.Mismatch),
		it("/etc/kubernetes/a", imapolicy.Mismatch), it("/etc/kubernetes/b", imapolicy.Mismatch))
	s.want(trust.Untrusted, 45, true)
	if s.tr.Findings[0].Type != trust.CriticalScore {
		t.Fatalf("%+v", s.tr.Findings)
	}
}

func TestTrackOneFailedCycle(t *testing.T) {
	s := newSim(t)
	s.ok()
	s.fail(StateUnreachable)
	if s.tr.Unattested {
		t.Fatal("one failed cycle must not make the node unattested")
	}
	s.ok()
	s.want(trust.Healthy, 100, false)
}

func TestTrackEvidenceMissing(t *testing.T) {
	s := newSim(t)
	s.ok()
	s.fail(StateUnreachable) // t+2m
	s.fail(StateUnreachable) // t+3m: unattested
	if !s.tr.Unattested || s.tr.Critical {
		t.Fatalf("unattested=%t critical=%t", s.tr.Unattested, s.tr.Critical)
	}
	k := s.fail(StateUnreachable) // t+4m: two minutes after the first failure
	if !has(k, "critical") {
		t.Fatalf("events %v", k)
	}
	if s.tr.Findings[0].Type != trust.CriticalMissing {
		t.Fatalf("%+v", s.tr.Findings)
	}
	s.ok()
	s.want(trust.Healthy, 100, true) // a later quote does not undo it
}

func TestTrackBadEvidence(t *testing.T) {
	s := newSim(t)
	s.ok()
	s.fail(StateBadEvidence)
	s.want(trust.Healthy, 100, true)
	if s.tr.Findings[0].Type != trust.CriticalEvidence {
		t.Fatalf("%+v", s.tr.Findings)
	}
}

func TestTrackCounterRollback(t *testing.T) {
	s := newSim(t)
	s.ok()
	s.reset--
	s.ok()
	s.want(trust.Healthy, 100, true)
	if s.tr.Findings[0].Type != trust.CriticalCounter {
		t.Fatalf("%+v", s.tr.Findings)
	}
}

func TestTrackRepeatedCriticalLoggedOnce(t *testing.T) {
	s := newSim(t)
	s.ok()
	s.ok(it("/usr/bin/kubelet", imapolicy.Mismatch))
	if k := s.ok(it("/usr/bin/kubelet", imapolicy.Mismatch)); has(k, "critical") {
		t.Fatalf("logged again: %v", k)
	}
}
