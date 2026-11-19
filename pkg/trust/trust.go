// Package trust is the trust engine of blueprint Section 7: it turns the
// classified IMA measurements of a node into critical findings (7.2) and a
// severity-weighted 0-100 score (7.3), maps the score to a tier, and labels
// score drops (7.4). It is cloud-neutral and has no state of its own; the
// verifier keeps the per-node state (pkg/verifier, Track).
package trust

import (
	"fmt"
	"math"
	"path"
	"sort"
	"strings"
	"time"

	"nodetrust/pkg/imapolicy"
)

// Component is one weighted part of the score (blueprint 7.3).
type Component struct {
	Name      string  `json:"name"`
	Weight    float64 `json:"weight"`
	Tolerance int     `json:"tolerance"` // mismatched files at which the component reaches 0
}

// Component names.
const (
	Binaries   = "system-binaries"
	Kubernetes = "kubernetes-config"
	SysConfig  = "system-config"
	Runtime    = "runtime-config"
	Security   = "security-policy"
)

// Components in the order of the blueprint's table. Weights add up to 100.
var Components = []Component{
	{Binaries, 30, 3},
	{Kubernetes, 25, 2},
	{SysConfig, 20, 4},
	{Runtime, 15, 1},
	{Security, 10, 2},
}

// rule maps a path to a component. A pattern ending in "/" matches the
// directory and everything below it; any other pattern matches that path
// exactly, or, if it ends in "*", any path starting with the rest.
type rule struct{ pattern, component string }

// componentRules are checked in order; the first match wins, so specific
// paths come before the directories that contain them. Anything that no rule
// matches is counted under system binaries: that covers /usr, /bin, /sbin,
// /lib and executables anywhere else (an ima-ng entry does not say whether a
// file was executed or read, so an unknown file outside the config paths is
// treated as an unknown executable).
var componentRules = []rule{
	// Kubernetes config
	{"/etc/kubernetes/", Kubernetes},
	{"/var/lib/kubelet/config.yaml", Kubernetes},
	{"/var/lib/kubelet/kubeadm-flags.env", Kubernetes},
	{"/etc/default/kubelet", Kubernetes},
	{"/etc/cni/net.d/", Kubernetes},
	{"/etc/systemd/system/kubelet.service.d/", Kubernetes},
	{"/usr/lib/systemd/system/kubelet.service.d/", Kubernetes},
	{"/var/lib/kubelet/", Kubernetes}, // anything else kubelet keeps; its config files above
	// container runtime config
	{"/etc/containerd/", Runtime},
	{"/etc/crictl.yaml", Runtime},
	// security policy
	{"/etc/apparmor.d/", Security},
	{"/etc/apparmor/", Security},
	{"/etc/audit/", Security},
	{"/etc/falco/", Security},
	{"/etc/nodetrust/", Security},
	// system config: units, cron, accounts, sudo, ssh, PAM, loader and
	// kernel settings, and the rest of /etc
	{"/usr/lib/systemd/system/", SysConfig},
	{"/lib/systemd/system/", SysConfig},
	{"/usr/lib/systemd/user/", SysConfig},
	{"/var/spool/cron/", SysConfig},
	{"/etc/", SysConfig},
}

func (r rule) match(p string) bool {
	switch {
	case strings.HasSuffix(r.pattern, "/"):
		return strings.HasPrefix(p, r.pattern) || p == strings.TrimSuffix(r.pattern, "/")
	case strings.HasSuffix(r.pattern, "*"):
		return strings.HasPrefix(p, strings.TrimSuffix(r.pattern, "*"))
	default:
		return p == r.pattern
	}
}

// ComponentOf returns the component a path counts against.
func ComponentOf(p string) string {
	for _, r := range componentRules {
		if r.match(p) {
			return r.component
		}
	}
	return Binaries
}

// Critical finding types (blueprint 7.2). The verifier adds the evidence
// types (bad quote, missing evidence, counters going back) and the boot
// type; the measurement types come from Critical below.
const (
	CriticalBinary   = "critical-binary"  // kubelet, containerd, the shim, runc, the agent or Falco
	CriticalBootFile = "boot-file"        // a file in /boot or the EFI partition that is not the reference
	CriticalModule   = "kernel-module"    // a kernel module that is not the reference
	CriticalPreload  = "ld-so-preload"    // /etc/ld.so.preload exists
	CriticalIMA      = "ima-policy"       // the IMA policy measurement changed
	CriticalBoot     = "boot"             // boot PCRs or Secure Boot differ from the boot policy
	CriticalEvidence = "bad-evidence"     // the quote, nonce or IMA replay does not verify
	CriticalMissing  = "evidence-missing" // no valid quote for longer than the grace time
	CriticalCounter  = "counter-rollback" // a TPM counter went backwards
	CriticalScore    = "score"            // the score fell below 50 (tier Untrusted)
)

// CriticalBinaries are the base names of the files whose change is critical.
// Matching by base name also catches a copy run from another directory.
var CriticalBinaries = map[string]bool{
	"kubelet": true, "containerd": true, "containerd-shim-runc-v2": true,
	"runc": true, "nodetrust-agent": true, "falco": true,
}

// IMAPolicyPath is where the golden AMI keeps the IMA policy it loads.
const IMAPolicyPath = "/etc/nodetrust/ima-policy"

// Finding is one critical finding.
type Finding struct {
	Type   string `json:"type"`
	Path   string `json:"path,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Detail string `json:"detail"`
}

func (f Finding) String() string {
	if f.Path != "" {
		return f.Type + " " + f.Path + ": " + f.Detail
	}
	return f.Type + ": " + f.Detail
}

// File is one measured file that counts against the score.
type File struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	Class     string `json:"class"` // imapolicy.Mismatch or imapolicy.Unknown
	Component string `json:"component"`
}

// bad reports whether a class means the file is not what the reference says.
// Changed and Runtime files are allowed by the runtime policy; a Violation
// item is a time-of-measure/time-of-use event the policy allows.
func bad(class string) bool { return class == imapolicy.Mismatch || class == imapolicy.Unknown }

func isModule(p string) bool {
	for _, s := range []string{".ko", ".ko.zst", ".ko.xz", ".ko.gz"} {
		if strings.HasSuffix(p, s) {
			return true
		}
	}
	return false
}

// Critical returns the critical finding for one classified measurement, if
// it is one.
func Critical(it imapolicy.Item) (Finding, bool) {
	p := it.Path
	f := Finding{Path: p, SHA256: it.SHA256}
	switch {
	case p == "/etc/ld.so.preload" && it.Class != imapolicy.Match:
		f.Type, f.Detail = CriticalPreload, "/etc/ld.so.preload was read"
	case !bad(it.Class):
		return Finding{}, false
	case CriticalBinaries[path.Base(p)]:
		f.Type, f.Detail = CriticalBinary, it.Class+": not the reference binary"
	case p == IMAPolicyPath:
		f.Type, f.Detail = CriticalIMA, it.Class+": the IMA policy is not the reference"
	case strings.HasPrefix(p, "/boot/"):
		f.Type, f.Detail = CriticalBootFile, it.Class+": not in the manifest for /boot or the EFI partition"
	case isModule(p):
		f.Type, f.Detail = CriticalModule, it.Class+": kernel module not in the reference"
	default:
		return Finding{}, false
	}
	return f, true
}

// Assess splits classified measurements into critical findings and the
// files that count against the score. A file that is critical does not also
// count against the score (blueprint 7.2: critical findings skip scoring).
// Each path is reported once, with its first bad hash.
func Assess(items []imapolicy.Item) (critical []Finding, files []File) {
	seenF, seenC := map[string]bool{}, map[string]bool{}
	for _, it := range items {
		if f, ok := Critical(it); ok {
			if !seenC[f.Type+" "+f.Path] {
				seenC[f.Type+" "+f.Path] = true
				critical = append(critical, f)
			}
			continue
		}
		if !bad(it.Class) || seenF[it.Path] {
			continue
		}
		seenF[it.Path] = true
		files = append(files, File{Path: it.Path, SHA256: it.SHA256, Class: it.Class, Component: ComponentOf(it.Path)})
	}
	return critical, files
}

// Breakdown is the score and what it is made of.
type Breakdown struct {
	Score      float64            `json:"score"`
	Components map[string]float64 `json:"components"` // points left per component
	Mismatched map[string]int     `json:"mismatched"` // mismatched files per component
}

// Score computes S = sum over components of w * max(0, 1 - m/t), where m is
// the number of distinct mismatched files in the component.
func Score(files []File) Breakdown {
	b := Breakdown{Components: map[string]float64{}, Mismatched: map[string]int{}}
	seen := map[string]bool{}
	for _, f := range files {
		if seen[f.Path] {
			continue
		}
		seen[f.Path] = true
		b.Mismatched[f.Component]++
	}
	for _, c := range Components {
		pts := c.Weight * math.Max(0, 1-float64(b.Mismatched[c.Name])/float64(c.Tolerance))
		b.Components[c.Name] = round(pts)
		b.Score += pts
	}
	b.Score = round(b.Score)
	return b
}

// round keeps scores to two decimals, so 72.5 prints as 72.5 and sums of
// thirds do not drift.
func round(x float64) float64 { return math.Round(x*100) / 100 }

// Tiers (blueprint 7.3).
const (
	Healthy   = "healthy"   // above 90
	Warning   = "warning"   // 75 to 90
	Degraded  = "degraded"  // 50 to below 75
	Untrusted = "untrusted" // below 50: handled as critical
)

// TierOf maps a score to its tier.
func TierOf(score float64) string {
	switch {
	case score > 90:
		return Healthy
	case score >= 75:
		return Warning
	case score >= 50:
		return Degraded
	default:
		return Untrusted
	}
}

// Rank orders tiers from best (0) to worst.
func Rank(tier string) int {
	switch tier {
	case Healthy:
		return 0
	case Warning:
		return 1
	case Degraded:
		return 2
	default:
		return 3
	}
}

// Drift labels (blueprint 7.4).
const (
	Sudden       = "sudden"       // a drop of 15 or more in one cycle
	Isolated     = "isolated"     // a smaller drop with no other drop in the window
	Gradual      = "gradual"      // three or more drops in the window, together at least 10
	Unclassified = "unclassified" // a smaller drop that fits neither (see Classify)
)

// Drift classification parameters (blueprint 7.4). The blueprint's window
// is 30 cycles at the default 60 s interval. With adaptive intervals a node
// that changed is challenged every 15 s, so a window counted in cycles
// would shrink to 7.5 minutes exactly when drift matters; it is kept as
// time instead: 30 minutes.
const (
	SuddenDrop   = 15.0
	DriftWindow  = 30 * time.Minute
	GradualDrops = 3
	GradualTotal = 10.0
)

// Drop is one fall of the score between two verified cycles.
type Drop struct {
	At    time.Time `json:"at"`
	Cycle int       `json:"cycle"`
	Size  float64   `json:"size"`
	Class string    `json:"class"`
}

// Classify labels a drop of size d at time at, given the earlier drops of
// the same node. The blueprint leaves one case open: a small drop that has
// another drop in the window but is not yet the third (or the drops add up
// to less than 10). That case is reported as Unclassified rather than forced
// into isolated or gradual.
func Classify(earlier []Drop, at time.Time, d float64) string {
	if d >= SuddenDrop {
		return Sudden
	}
	n, total := 1, d
	for _, e := range earlier {
		if age := at.Sub(e.At); age < DriftWindow && age >= 0 {
			n++
			total += e.Size
		}
	}
	switch {
	case n >= GradualDrops && total >= GradualTotal:
		return Gradual
	case n == 1:
		return Isolated
	default:
		return Unclassified
	}
}

// Summary is a one-line description of a breakdown, worst component first.
func (b Breakdown) Summary() string {
	var parts []string
	names := make([]string, 0, len(b.Mismatched))
	for n := range b.Mismatched {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s %d", n, b.Mismatched[n]))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("score %g", b.Score)
	}
	return fmt.Sprintf("score %g (%s)", b.Score, strings.Join(parts, ", "))
}
