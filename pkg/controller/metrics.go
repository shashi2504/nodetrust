package controller

// Prometheus metrics of the controller (blueprint Section 9): the
// containment phase of each node, the time from the finding to each
// containment step, and whether the circuit breaker is open.

import (
	"sort"

	"nodetrust/pkg/metrics"
)

// MetricStepSeconds is the time from a critical finding to each step done.
const MetricStepSeconds = "node_containment_step_seconds"

// NewMetrics declares the controller's histogram.
func NewMetrics() *metrics.Registry {
	r := metrics.New()
	r.Histogram(MetricStepSeconds, "Time from the critical finding to each containment step done (includes any wait for operator approval).",
		[]float64{1, 2, 5, 10, 30, 60, 120, 300, 600, 1800})
	return r
}

var phases = []string{PhaseCordoned, PhaseHeld, PhaseIsolated, PhaseSnapshot, PhaseReplaced, PhaseReleased, PhaseGone}

// Collect writes the gauges (register it with Metrics.Collect).
func (c *Controller) Collect(w *metrics.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ids := make([]string, 0, len(c.recs))
	for id, r := range c.recs {
		if r.Phase != "" {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		for _, p := range phases {
			w.Gauge("node_containment_phase", "1 for the node's current containment step.",
				metrics.Labels{"node": id, "phase": p}, b2f(c.recs[id].Phase == p))
		}
	}
	w.Gauge("trust_circuit_breaker_open", "1 while automatic containment is on hold for an operator.", nil, b2f(c.breaker))
	w.Gauge("trust_verifier_outage", "1 while no node has a fresh signed NodeTrust update.", nil, b2f(c.outage))
	w.Gauge("trust_controller_dry_run", "1 when the controller only logs.", nil, b2f(c.Cfg.DryRun))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (c *Controller) step(name string, seconds float64) {
	if c.Metrics != nil {
		c.Metrics.Observe(MetricStepSeconds, metrics.Labels{"step": name}, seconds)
	}
}
