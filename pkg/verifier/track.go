package verifier

import (
	"fmt"
	"sort"
	"time"

	"nodetrust/pkg/attest"
	"nodetrust/pkg/trust"
)

// Evidence rules (blueprint 6.3, with one change explained in README 4.4):
// one failed cycle gets an immediate retry; two failed cycles in a row make
// the node unattested (the controller puts the unattested taint back); a
// node with no valid quote for EvidenceGrace is critical (evidence missing).
// A quote that does not verify is critical at once.
const (
	EvidenceGrace  = 2 * time.Minute
	FailedToUnatt  = 2 // failed cycles in a row before the node is unattested
	TierUpCycles   = 3 // cycles a better tier must hold before it applies (blueprint 8.2)
	maxHistory     = 50
	maxFindings    = 20
	maxDropsKept   = 60
	maxFilesListed = 20
)

// Event is one entry in a node's history.
type Event struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail,omitempty"`
	Score  float64   `json:"score"`
}

// Track is the verifier's memory of one node across cycles, reboots and
// verifier restarts.
//
// Mismatched files are sticky: putting a file back does not take it off the
// list, and neither does a reboot (a reboot starts a clean IMA log, so
// without this an attacker could reboot the evidence away). Only a
// corrected manifest, which makes the file match, takes it off. Critical is
// sticky until the node is replaced.
type Track struct {
	InstanceID string `json:"instance_id"`

	Score      float64               `json:"score"`
	Tier       string                `json:"tier"`
	Components map[string]float64    `json:"components,omitempty"`
	Mismatched map[string]int        `json:"mismatched,omitempty"`
	Files      map[string]trust.File `json:"files,omitempty"` // sticky, by path

	Critical   bool            `json:"critical"`
	CriticalAt time.Time       `json:"critical_at,omitempty"`
	Findings   []trust.Finding `json:"findings,omitempty"` // first findings, in order

	Unattested       bool   `json:"unattested"` // no verified quote yet, or evidence currently missing
	UnattestedReason string `json:"unattested_reason,omitempty"`

	Seen            bool   `json:"seen"` // counters below are from a verified quote
	ResetCount      uint32 `json:"reset_count"`
	RestartCount    uint32 `json:"restart_count"`
	Clock           uint64 `json:"clock"`
	FirmwareVersion uint64 `json:"firmware_version"`

	FailStreak  int       `json:"fail_streak"` // failed cycles in a row
	FailingFrom time.Time `json:"failing_from,omitempty"`

	Cycles      int          `json:"cycles"` // verified cycles
	Reboots     int          `json:"reboots"`
	LastQuote   time.Time    `json:"last_quote,omitempty"`
	PendingTier string       `json:"pending_tier,omitempty"`
	PendingFor  int          `json:"pending_for,omitempty"`
	Drops       []trust.Drop `json:"drops,omitempty"`
	History     []Event      `json:"history"`

	// Replay is where the incremental IMA check stands in this boot.
	Replay ReplayState `json:"replay"`
	// LastChange is the last reboot or score drop; a node that changed
	// recently is challenged more often (blueprint 6.2).
	LastChange time.Time `json:"last_change,omitempty"`
	// SweepPending is set while the full sweep of this boot has not yet
	// finished within its time budget; the next challenge sweeps in full
	// again (opening an unchanged file is cheap, so each pass gets further).
	SweepPending bool `json:"sweep_pending,omitempty"`
	// PublishSeq is the sequence number of the last NodeTrust update
	// (step 4.7); it only grows, so the controller can refuse a replay.
	PublishSeq uint64 `json:"publish_seq,omitempty"`
}

// Observation is one cycle for an enrolled node.
type Observation struct {
	At      time.Time
	State   string            // StateVerified, StateBadEvidence or StateUnreachable
	Reason  string            // why, for a failed cycle
	Quote   *attest.QuoteInfo // the verified quote
	Verdict *Verdict          // what the verified quote shows
	// Still reports whether a remembered file is still bad under the
	// manifest and policy in force now; nil keeps every file.
	Still func(trust.File) bool
	// Next is the replay state after the verified quote.
	Next *ReplayState
}

// NewTrack starts the record of a newly enrolled node: unattested until its
// first verified quote.
func NewTrack(id string) *Track {
	return &Track{InstanceID: id, Score: 100, Tier: trust.Healthy, Unattested: true,
		UnattestedReason: "no verified quote yet"}
}

func (t *Track) event(at time.Time, kind, detail string) {
	t.History = append(t.History, Event{At: at.UTC(), Kind: kind, Detail: detail, Score: t.Score})
	if len(t.History) > maxHistory {
		t.History = t.History[len(t.History)-maxHistory:]
	}
}

// critical records a critical finding. The first one marks the node
// critical; later ones are kept (up to maxFindings) and logged once each.
func (t *Track) critical(at time.Time, f trust.Finding) {
	for _, g := range t.Findings {
		if g.Type == f.Type && g.Path == f.Path {
			return
		}
	}
	if len(t.Findings) < maxFindings {
		t.Findings = append(t.Findings, f)
	}
	if !t.Critical {
		t.Critical, t.CriticalAt = true, at.UTC()
	}
	t.event(at, "critical", f.String())
}

// Observe folds one cycle into the track and returns the events it added.
func (t *Track) Observe(o Observation) []Event {
	before := len(t.History)
	switch o.State {
	case StateUnreachable:
		t.FailStreak++
		if t.FailStreak == 1 {
			t.FailingFrom = o.At.UTC()
			t.event(o.At, "failed-cycle", o.Reason)
		}
		if t.FailStreak == FailedToUnatt {
			t.Unattested, t.UnattestedReason = true, fmt.Sprintf("no valid quote for %d cycles: %s", t.FailStreak, o.Reason)
			t.event(o.At, "unattested", t.UnattestedReason)
		}
		if t.FailStreak >= FailedToUnatt && o.At.Sub(t.FailingFrom) >= EvidenceGrace {
			t.critical(o.At, trust.Finding{Type: trust.CriticalMissing,
				Detail: fmt.Sprintf("no valid quote since %s (%d failed cycles)", t.FailingFrom.Format(time.RFC3339), t.FailStreak)})
		}
	case StateBadEvidence:
		t.critical(o.At, trust.Finding{Type: trust.CriticalEvidence, Detail: o.Reason})
	case StateVerified:
		if t.FailStreak > 0 {
			t.event(o.At, "reachable", fmt.Sprintf("verified quote again after %d failed cycle(s)", t.FailStreak))
			t.FailStreak, t.FailingFrom = 0, time.Time{}
		}
		if o.Quote != nil {
			t.counters(o.At, o.Quote)
		}
		t.Cycles++
		if o.Verdict != nil {
			for _, f := range o.Verdict.Critical {
				t.critical(o.At, f)
			}
			t.score(o)
		}
		t.Unattested, t.UnattestedReason = false, ""
		t.Seen, t.LastQuote = true, o.At.UTC()
		if o.Next != nil {
			t.Replay = *o.Next
		}
	}
	return append([]Event(nil), t.History[before:]...)
}

// score merges the cycle's files into the sticky set, recomputes the score,
// labels a drop and applies the tier with hysteresis.
func (t *Track) score(o Observation) {
	if t.Files == nil {
		t.Files = map[string]trust.File{}
	}
	for p, f := range t.Files {
		if o.Still != nil && !o.Still(f) {
			delete(t.Files, p)
			t.event(o.At, "cleared", f.Path+" no longer counts (the manifest, runtime policy or join reference now allows it)")
		}
	}
	var added []string
	for _, f := range o.Verdict.Files {
		if _, ok := t.Files[f.Path]; !ok {
			t.Files[f.Path] = f
			added = append(added, f.Class+" "+f.Path)
		}
	}
	files := make([]trust.File, 0, len(t.Files))
	for _, f := range t.Files {
		files = append(files, f)
	}
	b := trust.Score(files)
	prev := t.Score
	t.Score, t.Components, t.Mismatched = b.Score, b.Components, b.Mismatched
	if d := prev - b.Score; d > 0 {
		t.LastChange = o.At.UTC()
		cls := trust.Classify(t.Drops, o.At, d)
		t.Drops = append(t.Drops, trust.Drop{At: o.At.UTC(), Cycle: t.Cycles, Size: d, Class: cls})
		if len(t.Drops) > maxDropsKept {
			t.Drops = t.Drops[len(t.Drops)-maxDropsKept:]
		}
		sort.Strings(added)
		t.event(o.At, "drift-"+cls, fmt.Sprintf("score %g -> %g: %v", prev, b.Score, added))
	} else if len(added) > 0 {
		// A component already at zero: the file is recorded, the score does not move.
		t.event(o.At, "files", fmt.Sprintf("%v (component already at its tolerance)", added))
	}
	target := trust.TierOf(b.Score)
	if target == trust.Untrusted {
		t.critical(o.At, trust.Finding{Type: trust.CriticalScore, Detail: b.Summary()})
	}
	switch {
	case trust.Rank(target) > trust.Rank(t.Tier): // worse: at once
		t.event(o.At, "tier", t.Tier+" -> "+target)
		t.Tier, t.PendingTier, t.PendingFor = target, "", 0
	case trust.Rank(target) == trust.Rank(t.Tier):
		t.PendingTier, t.PendingFor = "", 0
	default: // better: only after it holds for TierUpCycles cycles
		if t.PendingTier == target {
			t.PendingFor++
		} else {
			t.PendingTier, t.PendingFor = target, 1
		}
		if t.PendingFor >= TierUpCycles {
			t.event(o.At, "tier", fmt.Sprintf("%s -> %s after %d cycles", t.Tier, target, t.PendingFor))
			t.Tier, t.PendingTier, t.PendingFor = target, "", 0
		}
	}
}

// counters compares the TPM's reset, restart and clock values with the last
// verified quote. They live in the TPM and are signed in every quote. A
// reboot (resetCount up) is only an event: the new boot was checked in full
// in this same quote (boot event log against the boot policy, new IMA log).
func (t *Track) counters(at time.Time, q *attest.QuoteInfo) {
	if t.Seen {
		rollback := func(what string, a, b uint64) {
			t.critical(at, trust.Finding{Type: trust.CriticalCounter, Detail: fmt.Sprintf("TPM %s went back %d -> %d", what, a, b)})
		}
		switch {
		case q.ResetCount < t.ResetCount:
			rollback("resetCount", uint64(t.ResetCount), uint64(q.ResetCount))
		case q.ResetCount > t.ResetCount:
			t.Reboots++
			t.LastChange = at.UTC()
			t.event(at, "reboot", fmt.Sprintf("TPM resetCount %d -> %d; the new boot was checked in full", t.ResetCount, q.ResetCount))
		case q.RestartCount < t.RestartCount:
			rollback("restartCount", uint64(t.RestartCount), uint64(q.RestartCount))
		case q.RestartCount > t.RestartCount:
			t.event(at, "tpm-restart", fmt.Sprintf("restartCount %d -> %d without a reset", t.RestartCount, q.RestartCount))
		case q.Clock < t.Clock:
			rollback("clock (same boot)", t.Clock, q.Clock)
		}
		if q.FirmwareVersion != t.FirmwareVersion {
			t.event(at, "tpm-firmware", fmt.Sprintf("TPM firmware %#x -> %#x", t.FirmwareVersion, q.FirmwareVersion))
		}
	}
	t.ResetCount, t.RestartCount, t.Clock, t.FirmwareVersion = q.ResetCount, q.RestartCount, q.Clock, q.FirmwareVersion
}

// SortedFiles returns the sticky files by path, at most n.
func (t *Track) SortedFiles(n int) []trust.File {
	out := make([]trust.File, 0, len(t.Files))
	for _, f := range t.Files {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if len(out) > n {
		out = out[:n]
	}
	return out
}
