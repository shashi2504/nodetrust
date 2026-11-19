// Package imapolicy classifies a node's IMA measurements against the signed
// reference manifest of its golden AMI (blueprint Phase 2, step 2.4).
//
// Every measurement (file path and SHA-256 from the attested part of the IMA
// log) falls in exactly one class:
//
//	match      path is a file in the manifest and the hash is the same
//	mismatch   path is a file in the manifest, the hash differs, and no rule
//	           allows that path to change
//	changed    path is in the manifest and differs, but a "mutable" rule
//	           allows it (for example /etc/hostname, written at first boot)
//	runtime    path is not in the manifest but a "runtime" rule expects it
//	           (state written while the node runs, such as kubelet files)
//	unknown    path is not in the manifest and no rule covers it
//	violation  IMA could not measure the file reliably (ToMToU or open-writers)
//	           on a path a rule covers; a violation anywhere else is unknown
//	aggregate  the boot_aggregate entry (checked against PCRs 0-9 in Phase 4)
//
// The IMA policy in the golden AMI skips overlayfs, so files inside
// containers never reach this check; container images are a separate
// control (image digests and admission policy).
package imapolicy

import (
	"bufio"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"nodetrust/pkg/ima"
	"nodetrust/pkg/manifest"
)

// Classes, in report order.
const (
	Match     = "match"
	Mismatch  = "mismatch"
	Changed   = "changed"
	Runtime   = "runtime"
	Unknown   = "unknown"
	Violation = "violation"
	Aggregate = "aggregate"
	// Join is a join-time file that matches the join reference or the
	// fleet consensus (pkg/joinref); set by the verifier, not by Classify.
	Join = "join"
)

// Classes lists every class in report order.
var Classes = []string{Match, Join, Changed, Runtime, Aggregate, Violation, Mismatch, Unknown}

// Measurement is one distinct (path, hash) pair from the attested log.
type Measurement struct {
	First     int    // index of the first log entry with this pair
	Count     int    // how many entries had it
	SHA256    string // hex; empty for a violation
	Path      string
	Violation bool
}

// Rule allows a path to differ from the manifest (mutable) or to be absent
// from it (runtime). Pattern is an exact path, a directory prefix ending in
// "/", or a path.Match glob. SHA256, when set, also limits the content to
// those hashes (for example only the empty file for a temp file).
type Rule struct {
	Pattern string   `json:"pattern"`
	SHA256  []string `json:"sha256,omitempty"`
	Why     string   `json:"why"`
}

// Policy is the runtime file policy (infra/phase2/runtime-policy.json).
type Policy struct {
	Mutable []Rule `json:"mutable"`
	Runtime []Rule `json:"runtime"`
}

// LoadPolicy reads and validates a policy file.
func LoadPolicy(b []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	for _, r := range append(append([]Rule{}, p.Mutable...), p.Runtime...) {
		if !strings.HasPrefix(r.Pattern, "/") {
			return nil, fmt.Errorf("policy: pattern %q must be absolute", r.Pattern)
		}
		if _, err := path.Match(r.Pattern, "/"); err != nil {
			return nil, fmt.Errorf("policy: bad pattern %q: %w", r.Pattern, err)
		}
		if r.Why == "" {
			return nil, fmt.Errorf("policy: pattern %q needs a reason", r.Pattern)
		}
		if r.Pattern == "/" {
			return nil, errors.New("policy: a rule for / would allow everything")
		}
		for _, h := range r.SHA256 {
			if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
				return nil, fmt.Errorf("policy: pattern %q: %q is not a lowercase SHA-256", r.Pattern, h)
			}
		}
	}
	return &p, nil
}

func (r Rule) matches(p, hash string) bool {
	if len(r.SHA256) > 0 {
		ok := false
		for _, h := range r.SHA256 {
			ok = ok || h == hash
		}
		if !ok {
			return false
		}
	}
	switch {
	case strings.HasSuffix(r.Pattern, "/"):
		return strings.HasPrefix(p, r.Pattern)
	case strings.ContainsAny(r.Pattern, "*?["):
		ok, _ := path.Match(r.Pattern, p)
		return ok
	default:
		return p == r.Pattern
	}
}

func first(rules []Rule, p, hash string) *Rule {
	for i := range rules {
		if rules[i].matches(p, hash) {
			return &rules[i]
		}
	}
	return nil
}

// Item is a classified measurement.
type Item struct {
	Measurement
	Class string
	Rule  string // pattern of the rule that allowed it, if any
}

// Result of a classification.
type Result struct {
	Items  []Item
	Counts map[string]int // distinct (path, hash) pairs per class
	Pass   bool           // no mismatch and no unknown
}

// Classify sorts measurements into classes.
func Classify(ms []Measurement, idx map[string]manifest.Entry, p *Policy) *Result {
	res := &Result{Counts: map[string]int{}}
	for _, m := range ms {
		it := Item{Measurement: m}
		switch {
		case m.Violation:
			// Expected for files written while root reads them (logs,
			// fresh certificates); anywhere else it is unexplained.
			if r := first(append(append([]Rule{}, p.Runtime...), p.Mutable...), m.Path, ""); r != nil {
				it.Class, it.Rule = Violation, r.Pattern
			} else {
				it.Class = Unknown
			}
		case m.Path == "boot_aggregate":
			it.Class = Aggregate
		default:
			e, inManifest := idx[m.Path]
			switch {
			case inManifest && e.Type == "file" && e.SHA256 == m.SHA256:
				it.Class = Match
			case inManifest:
				if r := first(p.Mutable, m.Path, m.SHA256); r != nil {
					it.Class, it.Rule = Changed, r.Pattern
				} else if r := first(p.Runtime, m.Path, m.SHA256); r != nil {
					it.Class, it.Rule = Changed, r.Pattern
				} else {
					it.Class = Mismatch
				}
			default:
				if r := first(p.Runtime, m.Path, m.SHA256); r != nil {
					it.Class, it.Rule = Runtime, r.Pattern
				} else if r := first(p.Mutable, m.Path, m.SHA256); r != nil {
					it.Class, it.Rule = Runtime, r.Pattern
				} else {
					it.Class = Unknown
				}
			}
		}
		res.Items = append(res.Items, it)
		res.Counts[it.Class]++
	}
	sort.SliceStable(res.Items, func(i, j int) bool { return res.Items[i].First < res.Items[j].First })
	res.Pass = res.Counts[Mismatch] == 0 && res.Counts[Unknown] == 0
	return res
}

// Without returns the measurements of ms whose (path, hash) pair is not in
// base. Used to look at what changed between two snapshots of one node.
func Without(ms, base []Measurement) []Measurement {
	seen := make(map[[2]string]bool, len(base))
	for _, b := range base {
		seen[[2]string{b.Path, b.SHA256}] = true
	}
	var out []Measurement
	for _, m := range ms {
		if !seen[[2]string{m.Path, m.SHA256}] {
			out = append(out, m)
		}
	}
	return out
}

// Snapshot is a measurements file written by ima_snapshot.py on a node.
type Snapshot struct {
	Meta         map[string]string
	Measurements []Measurement
}

// ReadSnapshot reads a measurements file (gzip or plain, detected from the
// content):
//
//	# key=value          (metadata lines)
//	first<TAB>count<TAB>sha256<TAB>path
//
// A violation has "-" as its hash.
func ReadSnapshot(name string) (*Snapshot, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer zr.Close()
		r = zr
	}
	s := &Snapshot{Meta: map[string]string{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		t := sc.Text()
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "# ") {
			if k, v, ok := strings.Cut(t[2:], "="); ok {
				s.Meta[k] = v
			}
			continue
		}
		parts := strings.SplitN(t, "\t", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("%s:%d: want 4 tab-separated fields", name, line)
		}
		firstIdx, err1 := strconv.Atoi(parts[0])
		count, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil || count < 1 {
			return nil, fmt.Errorf("%s:%d: bad index or count", name, line)
		}
		p, err := unescape(parts[3])
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", name, line, err)
		}
		m := Measurement{First: firstIdx, Count: count, Path: p}
		if parts[2] == "-" {
			m.Violation = true
		} else if len(parts[2]) != 64 {
			return nil, fmt.Errorf("%s:%d: hash is not SHA-256 hex", name, line)
		} else {
			m.SHA256 = parts[2]
		}
		s.Measurements = append(s.Measurements, m)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if s.Meta["format"] != "nodetrust-ima-snapshot/1" {
		return nil, fmt.Errorf("%s: not a nodetrust IMA snapshot (format %q)", name, s.Meta["format"])
	}
	return s, nil
}

// unescape reverses the escaping ima_snapshot.py applies to paths, so a path
// with a tab or newline in it cannot forge an extra field or line: \\, \t,
// \n, and \xHH for bytes that are not valid UTF-8.
func unescape(s string) (string, error) {
	if !strings.Contains(s, "\\") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 == len(s) {
			return "", errors.New("path ends in a lone backslash")
		}
		i++
		switch s[i] {
		case '\\':
			b.WriteByte('\\')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'x':
			if i+2 >= len(s) {
				return "", errors.New("short \\x escape in path")
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return "", fmt.Errorf("bad \\x escape in path: %w", err)
			}
			b.WriteByte(byte(v))
			i += 2
		default:
			return "", fmt.Errorf("unknown escape \\%c in path", s[i])
		}
	}
	return b.String(), nil
}

// FromLog turns the attested entries of an IMA log into distinct (path,
// hash) measurements, as ima_snapshot.py does on a node. Every entry must be
// ima-ng with a SHA-256 file digest.
func FromLog(entries []ima.Entry) ([]Measurement, error) {
	var out []Measurement
	at := map[[2]string]int{}
	for i := range entries {
		e := &entries[i]
		if e.PCR != ima.PCR {
			continue
		}
		var path, digest string
		viol := e.Violation()
		if e.TemplateName != "ima-ng" {
			return nil, fmt.Errorf("ima: entry %d has template %q, want ima-ng", i, e.TemplateName)
		}
		m, err := ima.DecodeNG(e.TemplateData)
		if err != nil {
			return nil, fmt.Errorf("ima: entry %d: %w", i, err)
		}
		path = string(m.Path)
		if !viol {
			if m.Algo != "sha256" || len(m.Digest) != 32 {
				return nil, fmt.Errorf("ima: entry %d has a %s file digest; boot with ima_hash=sha256", i, m.Algo)
			}
			digest = hex.EncodeToString(m.Digest)
		}
		k := [2]string{path, digest}
		if j, ok := at[k]; ok {
			out[j].Count++
			continue
		}
		at[k] = len(out)
		out = append(out, Measurement{First: i, Count: 1, SHA256: digest, Path: path, Violation: viol})
	}
	return out, nil
}
