// Package controller is the trust controller (blueprint Section 8, Phase 5).
// It reads the verifier's signed NodeTrust objects, checks each signature
// against the pinned key, and turns the result into actions:
//
//	healthy    no trust taints
//	warning    taint trust.k8s-attest.io/warning:PreferNoSchedule
//	degraded   taint trust.k8s-attest.io/degraded:NoSchedule, cordon, evict
//	           pods labelled trust.k8s-attest.io/sensitive=true
//	untrusted  as critical
//	critical   the critical path: cordon and taint
//	           trust.k8s-attest.io/critical:NoExecute, then isolate, snapshot,
//	           replace (AWS API) and delete the Node object
//	unattested taint trust.k8s-attest.io/unattested:NoSchedule
//
// with the safety controls of blueprint 8.4: a verifier outage is not node
// failure, a circuit breaker holds mass containment for an operator, and
// everything can run in dry-run (log only) mode.
package controller

import (
	"sort"
	"strconv"
	"strings"

	"nodetrust/pkg/nodetrust"
	"nodetrust/pkg/trust"
)

// Taint keys and the annotation that marks a cordon done by the controller.
const (
	Prefix          = "trust.k8s-attest.io/"
	TaintUnattested = Prefix + "unattested"
	TaintWarning    = Prefix + "warning"
	TaintDegraded   = Prefix + "degraded"
	TaintCritical   = Prefix + "critical"
	LabelSensitive  = Prefix + "sensitive"
	AnnCordoned     = Prefix + "cordoned-by"
	AnnTier         = Prefix + "tier"
)

// Taint is a Kubernetes node taint.
type Taint struct {
	Key    string `json:"key"`
	Value  string `json:"value,omitempty"`
	Effect string `json:"effect"`
}

// ours reports whether a taint key belongs to the controller.
func ours(key string) bool { return strings.HasPrefix(key, Prefix) }

// Spec is what the controller wants a node to look like.
type Spec struct {
	Taints      []Taint // the controller's taints only
	Cordon      bool    // cordon (and mark the cordon as ours)
	Uncordon    bool    // remove a cordon only if the controller set it
	EvictTagged bool    // evict pods labelled trust.k8s-attest.io/sensitive=true
	Critical    bool    // start or continue the critical path
	Reason      string  // one line, for logs and snapshot tags
}

// Desired maps a node's checked state to its spec. st is nil when there is
// no valid NodeTrust yet; stale means the last valid one is too old.
func Desired(st *nodetrust.State, stale bool) Spec {
	switch {
	case st == nil:
		return Spec{Taints: []Taint{{Key: TaintUnattested, Effect: "NoSchedule"}}, Reason: "no valid signed NodeTrust yet"}
	case st.Critical || st.Tier == trust.Untrusted:
		return Spec{Critical: true, Cordon: true, Taints: []Taint{{Key: TaintCritical, Effect: "NoExecute"}}, Reason: reason(st)}
	}
	var s Spec
	if st.Unattested || stale {
		s.Taints = append(s.Taints, Taint{Key: TaintUnattested, Effect: "NoSchedule"})
		s.Reason = "unattested: " + st.UnattestedReason
		if stale {
			s.Reason = "no fresh signed NodeTrust update"
		}
	}
	switch st.Tier {
	case trust.Warning:
		s.Taints = append(s.Taints, Taint{Key: TaintWarning, Effect: "PreferNoSchedule"})
	case trust.Degraded:
		s.Taints = append(s.Taints, Taint{Key: TaintDegraded, Effect: "NoSchedule"})
		s.Cordon, s.EvictTagged = true, true
	}
	if !s.Cordon {
		s.Uncordon = true
	}
	if s.Reason == "" {
		s.Reason = reason(st)
	}
	return s
}

// reason is a one-line description of a signed state.
func reason(st *nodetrust.State) string {
	if len(st.Findings) > 0 {
		var parts []string
		for _, f := range st.Findings {
			parts = append(parts, f.String())
		}
		return strings.Join(parts, "; ")
	}
	return st.Tier + ", score " + trimFloat(st.Score)
}

func trimFloat(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

// Merge returns the node's taints with the controller's replaced by want,
// sorted for stable patches.
func Merge(have, want []Taint) []Taint {
	var out []Taint
	for _, t := range have {
		if !ours(t.Key) {
			out = append(out, t)
		}
	}
	out = append(out, want...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// SameTaints compares two taint lists as sets.
func SameTaints(a, b []Taint) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[Taint]int{}
	for _, t := range a {
		m[t]++
	}
	for _, t := range b {
		m[t]--
		if m[t] < 0 {
			return false
		}
	}
	return true
}
