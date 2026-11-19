package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"nodetrust/pkg/bootpolicy"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/manifest"
	"nodetrust/pkg/protocol"
	"nodetrust/pkg/trust"
)

// Worker is one node as the cloud control plane describes it. None of these
// fields come from the node itself.
type Worker struct {
	InstanceID   string `json:"instance_id"`
	Addr         string `json:"addr"` // agent address, host:port
	AMI          string `json:"ami"`
	RootVolumeID string `json:"root_volume_id"`
	Zone         string `json:"zone,omitempty"`
}

// JoinCheck classifies a join-time file (blueprint 10.4, pkg/joinref): it
// returns imapolicy.Join or imapolicy.Mismatch for a path it covers, and
// covered=false for any other path.
type JoinCheck func(path, sha256 string) (class string, covered bool)

// Verdict is what one verified quote shows about a node: the critical
// findings (blueprint 7.2) and the files that count against the score (7.3).
// The score itself is kept per node across cycles (Track), because
// mismatches are sticky.
type Verdict struct {
	Clean    bool                  `json:"clean"` // no critical finding and no file against the score
	Critical []trust.Finding       `json:"critical,omitempty"`
	Files    []trust.File          `json:"files,omitempty"`
	IMA      map[string]int        `json:"ima"`              // distinct (path, hash) pairs per class
	Boot     string                `json:"boot"`             // "pass", "fail", "unchanged" (incremental) or "not checked"
	Initrd   string                `json:"initrd,omitempty"` // what the kernel got, from the boot log
	New      int                   `json:"new"`              // IMA entries newly attested by this quote
	Canary   string                `json:"canary,omitempty"` // "found", "missing" or "not asked"
	Sweep    *protocol.SweepReport `json:"sweep,omitempty"`
	MountNS  int                   `json:"mount_namespaces,omitempty"`
}

// maxListed bounds the findings and files a verdict lists.
const maxListed = 20

// Judge checks the content of a verified quote: the IMA measurements against
// the AMI's signed manifest and the runtime policy, and the boot event log
// against the boot policy (nil skips the boot check). The quote itself
// (signature, nonce, PCRs, log replay) was checked by CheckQuote.
func Judge(q *QuoteResult, w Worker, tr *manifest.Trusted, rt *imapolicy.Policy, bp *bootpolicy.Policy, jc JoinCheck) *Verdict {
	v := &Verdict{IMA: map[string]int{}, Boot: "not checked", New: len(q.IMAEntries), Canary: "not asked", Sweep: q.Sweep}
	ms, err := imapolicy.FromLog(q.IMAEntries)
	if err != nil {
		// The log replayed to the quoted PCR 10, so this is a log the
		// golden AMI cannot produce (another template or hash).
		v.Critical = append(v.Critical, trust.Finding{Type: trust.CriticalEvidence, Detail: "ima log: " + err.Error()})
	} else {
		r := imapolicy.Classify(ms, tr.Index, rt)
		if jc != nil {
			r.Counts = map[string]int{}
			for i := range r.Items {
				it := &r.Items[i]
				// The AMI's own version of a file (in the manifest) stays a
				// match: some join paths, like /opt/cni/bin, hold files from
				// the AMI that Calico replaces at join.
				if it.Class != imapolicy.Aggregate && it.Class != imapolicy.Match {
					// A violation has no hash; jc says whether its path is a
					// join file, where a read during the write is expected
					// (as the runtime policy allowed before step 4.6).
					if c, ok := jc(it.Path, it.SHA256); ok {
						it.Class, it.Rule = c, "join reference"
					}
				}
				r.Counts[it.Class]++
			}
		}
		v.IMA = r.Counts
		v.Critical, v.Files = trust.Assess(r.Items)
	}

	// The canary (blueprint 10.3): an entry for the canary file with the hash
	// of this challenge's value must be in the quoted log, or IMA has stopped
	// recording.
	if len(q.Canary) > 0 {
		want := sha256.Sum256(q.Canary)
		v.Canary = "missing"
		for _, m := range ms {
			if m.Path == protocol.CanaryPath && m.SHA256 == hex.EncodeToString(want[:]) {
				v.Canary = "found"
				break
			}
		}
		if v.Canary == "missing" {
			v.Critical = append(v.Critical, trust.Finding{Type: trust.CriticalCanary, Path: protocol.CanaryPath,
				Detail: "the canary is not in the quoted IMA log (agent says: " + q.CanaryStatus + ")"})
		}
	}
	if q.MountsAsked {
		v.Critical = append(v.Critical, trust.CheckMounts(q.Mounts)...)
		if q.Mounts != nil {
			v.MountNS = len(q.Mounts.Namespaces)
		}
	}

	if bp != nil {
		switch {
		case q.BootChanged:
			v.Boot = "fail"
			v.Critical = append(v.Critical, trust.Finding{Type: trust.CriticalBoot, Detail: "boot PCRs changed since the start of this boot"})
		case q.BootLog == nil && q.Next.Valid && q.Next.BootPCRs != nil:
			v.Boot = "unchanged" // checked against the event log at the start of the boot
		case q.BootLog == nil:
			v.Boot = "fail"
			v.Critical = append(v.Critical, trust.Finding{Type: trust.CriticalBoot, Detail: "the agent sent no boot event log"})
		default:
			r := bootpolicy.Evaluate(bp, &bootpolicy.Input{Log: q.BootLog, Quoted: q.PCRs, Manifest: tr.Index,
				AMI: w.AMI, RootVolumeID: w.RootVolumeID})
			v.Initrd = r.Initrd
			if r.Pass() {
				v.Boot = "pass"
			} else {
				v.Boot = "fail"
				for _, f := range r.Findings {
					if !f.OK {
						v.Critical = append(v.Critical, trust.Finding{Type: trust.CriticalBoot,
							Detail: fmt.Sprintf("pcr %d %s: %s", f.PCR, f.Check, f.Detail)})
					}
				}
			}
		}
	}
	v.Clean = len(v.Critical) == 0 && len(v.Files) == 0
	return v
}

// Summary is a one-line description of a verdict for logs.
func (v *Verdict) Summary() string {
	s := fmt.Sprintf("%d new: %d match, %d changed, %d runtime; boot %s; canary %s",
		v.New, v.IMA[imapolicy.Match], v.IMA[imapolicy.Changed], v.IMA[imapolicy.Runtime], v.Boot, v.Canary)
	if v.Sweep != nil {
		s += fmt.Sprintf("; sweep %d files", v.Sweep.Opened)
		if v.Sweep.Partial {
			s += " (partial)"
		}
	}
	if v.MountNS > 0 {
		s += fmt.Sprintf("; %d mount namespaces", v.MountNS)
	}
	if v.Clean {
		return "clean (" + s + ")"
	}
	var parts []string
	for i, f := range v.Critical {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("+%d more critical", len(v.Critical)-3))
			break
		}
		parts = append(parts, "critical "+f.String())
	}
	for i, f := range v.Files {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("+%d more files", len(v.Files)-3))
			break
		}
		parts = append(parts, f.Class+" "+f.Path+" ("+f.Component+")")
	}
	return strings.Join(parts, "; ") + " (" + s + ")"
}

// trim bounds the lists kept in a verdict.
func (v *Verdict) trim() {
	if len(v.Critical) > maxListed {
		v.Critical = v.Critical[:maxListed]
	}
	if len(v.Files) > maxListed {
		v.Files = v.Files[:maxListed]
	}
}
