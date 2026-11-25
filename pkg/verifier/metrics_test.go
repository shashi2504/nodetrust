package verifier

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"nodetrust/pkg/imapolicy"
)

// Every Section 9 metric of the verifier, from cycles like the live ones:
// clean, an unknown binary (warning), a fake kubelet (critical), an
// unreachable cycle.
func TestVerifierMetrics(t *testing.T) {
	now := t0.Add(10 * time.Minute)
	d := &Daemon{StateDir: t.TempDir(), RuntimePolicy: &imapolicy.Policy{}, Metrics: NewMetrics(), Now: func() time.Time { return now }}
	if err := d.Load(); err != nil {
		t.Fatal(err)
	}
	d.Metrics.Collect(d.Collect)
	w := Worker{InstanceID: "i-1", Addr: "10.42.17.24:9443", AMI: "ami-g"}
	d.enrolled["i-1"] = &Enrolled{InstanceID: "i-1"}
	cycle := func(n int, st string, items ...imapolicy.Item) {
		ob := Observation{At: t0.Add(time.Duration(n) * time.Minute), State: st}
		if st == StateVerified {
			ob.Quote, ob.Verdict = q(1, 0, uint64(n)), verdict(items...)
		}
		o := &outcome{w: w, obs: []Observation{ob}}
		if st == StateVerified {
			o.q = &QuoteResult{Quote: ob.Quote}
		}
		d.observe(o)
	}
	cycle(1, StateVerified)
	cycle(2, StateVerified, it("/usr/local/bin/x", imapolicy.Unknown))
	cycle(3, StateVerified, it("/usr/local/bin/x", imapolicy.Unknown), it("/usr/local/bin/kubelet", imapolicy.Unknown))
	cycle(4, StateUnreachable)
	d.duration("i-1", 0.7)

	var b bytes.Buffer
	d.Metrics.Write(&b)
	out := b.String()
	for _, want := range []string{
		`node_trust_score{node="i-1"} 90`,
		`node_trust_tier{node="i-1",tier="warning"} 1`,
		`node_trust_tier{node="i-1",tier="healthy"} 0`,
		`node_trust_component_score{component="system-binaries",node="i-1"} 20`,
		`node_trust_component_weight{component="system-binaries"} 30`,
		`node_trust_mismatched_files{component="system-binaries",node="i-1"} 1`,
		`node_trust_critical{node="i-1"} 1`,
		`node_trust_critical_findings_total{node="i-1",type="critical-binary"} 1`,
		`node_trust_drift_events_total{class="isolated",node="i-1"} 1`,
		`node_attestation_failures_total{node="i-1",reason="unreachable"} 1`,
		`node_attestation_duration_seconds_bucket{node="i-1",le="1"} 1`,
		`node_attestation_age_seconds{node="i-1"} 420`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %s", want)
		}
	}
	if t.Failed() {
		t.Log(out)
	}
}
