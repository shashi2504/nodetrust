package verifier

// Prometheus metrics of the verifier (blueprint Section 9). Counters and the
// challenge-duration histogram are updated as cycles happen; scores, tiers,
// components and attestation age are read from the node status at every
// scrape.

import (
	"sort"
	"strings"

	"nodetrust/pkg/metrics"
	"nodetrust/pkg/trust"
)

// Metric names.
const (
	MetricCriticalFindings = "node_trust_critical_findings_total"
	MetricDriftEvents      = "node_trust_drift_events_total"
	MetricFailures         = "node_attestation_failures_total"
	MetricDuration         = "node_attestation_duration_seconds"
)

// NewMetrics declares the verifier's counters and histogram.
func NewMetrics() *metrics.Registry {
	r := metrics.New()
	r.Counter(MetricCriticalFindings, "Critical findings by type (blueprint 7.2).")
	r.Counter(MetricDriftEvents, "Score drops by drift class: sudden, isolated, gradual, unclassified.")
	r.Counter(MetricFailures, "Failed challenges by reason: unreachable, bad-evidence, outage.")
	r.Histogram(MetricDuration, "Time from challenge to verdict (quote, logs, sweep and checks).",
		[]float64{0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30})
	return r
}

// count updates the counters from a node's new track events.
func (d *Daemon) count(node string, events []Event) {
	if d.Metrics == nil {
		return
	}
	// Every drift class exists from the first cycle at 0, so increase()
	// in an alert rule sees the first real event.
	for _, c := range []string{trust.Sudden, trust.Isolated, trust.Gradual, trust.Unclassified} {
		d.Metrics.Touch(MetricDriftEvents, metrics.Labels{"node": node, "class": c})
	}
	for _, ev := range events {
		switch {
		case ev.Kind == "critical":
			typ, _, _ := strings.Cut(ev.Detail, " ")
			typ = strings.TrimSuffix(typ, ":")
			d.Metrics.Inc(MetricCriticalFindings, metrics.Labels{"node": node, "type": typ})
		case strings.HasPrefix(ev.Kind, "drift-"):
			d.Metrics.Inc(MetricDriftEvents, metrics.Labels{"node": node, "class": strings.TrimPrefix(ev.Kind, "drift-")})
		}
	}
}

func (d *Daemon) failure(node, reason string) {
	if d.Metrics != nil {
		d.Metrics.Inc(MetricFailures, metrics.Labels{"node": node, "reason": reason})
	}
}

func (d *Daemon) duration(node string, s float64) {
	if d.Metrics != nil {
		d.Metrics.Observe(MetricDuration, metrics.Labels{"node": node}, s)
	}
}

var allTiers = []string{trust.Healthy, trust.Warning, trust.Degraded, trust.Untrusted}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Collect writes the gauges from the current node status (register it
// with Metrics.Collect).
func (d *Daemon) Collect(w *metrics.Writer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	ids := make([]string, 0, len(d.nodes))
	for id, n := range d.nodes {
		if n.Enrolled {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, c := range trust.Components {
		w.Gauge("node_trust_component_weight", "Full points of each score component (blueprint 7.3).", metrics.Labels{"component": c.Name}, c.Weight)
	}
	for _, id := range ids {
		n := d.nodes[id]
		l := metrics.Labels{"node": id}
		if n.Tier != "" {
			w.Gauge("node_trust_score", "Current trust score, 0-100.", l, n.Score)
			for _, t := range allTiers {
				w.Gauge("node_trust_tier", "1 for the node's current tier.", metrics.Labels{"node": id, "tier": t}, b2f(n.Tier == t))
			}
			for _, c := range trust.Components {
				cl := metrics.Labels{"node": id, "component": c.Name}
				w.Gauge("node_trust_component_score", "Points left in each score component.", cl, n.Components[c.Name])
				w.Gauge("node_trust_mismatched_files", "Mismatched or unknown files per component (sticky this boot).", cl, float64(n.Mismatched[c.Name]))
			}
		}
		w.Gauge("node_trust_critical", "1 while the node has a critical finding.", l, b2f(n.Critical))
		w.Gauge("node_trust_unattested", "1 while the node is unattested.", l, b2f(n.Unattested))
		if !n.LastQuote.IsZero() {
			w.Gauge("node_attestation_age_seconds", "Time since the last valid quote.", l, now.Sub(n.LastQuote).Seconds())
		}
		if n.Interval > 0 {
			w.Gauge("node_attestation_interval_seconds", "The node's current challenge interval.", l, n.Interval)
		}
	}
}
