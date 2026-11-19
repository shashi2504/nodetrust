// Package joinref checks the files a worker gets when it joins the cluster
// (blueprint 10.4). They are not in the AMI, so the signed manifest cannot
// cover them. Three layers, in order:
//
//  1. Precomputed: the expected content of each join file, per node. Files
//     the launch template writes come from the rendered template itself;
//     files kubeadm and kubelet write are captured from two fresh workers
//     when the cluster is built, compared, and kept as templates with the
//     node-specific values (instance ID, zone, address, host name) replaced
//     by placeholders. The verifier renders each template for the node it
//     checks.
//  2. Fleet consensus: for paths with no template (the CNI binaries Calico
//     installs), the hash most nodes on the same AMI report is the accepted
//     one, and a node with another hash is flagged.
//  3. Trust on first use: when no hash has a majority (one node, or a tie),
//     the hash the fleet saw first is accepted.
package joinref

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Placeholders a template may use.
const (
	PInstanceID = "${IID}"
	PZone       = "${AZ}"
	PAddress    = "${IP}"
	PHostname   = "${HOSTNAME}"
)

var placeholder = regexp.MustCompile(`\$\{[A-Za-z_]+\}`)

// File is the expected content of one join file: a template, or, for a
// binary the same on every node (the CNI plugins Calico installs), the list
// of its accepted SHA-256 hashes.
type File struct {
	Template string   `json:"template,omitempty"` // content, with placeholders
	SHA256   []string `json:"sha256,omitempty"`   // hex; used instead of Template when set
	Source   string   `json:"source"`             // where it came from, for people
}

// Reference is join-reference.json.
type Reference struct {
	Format    string          `json:"format"` // "nodetrust-join-reference/1"
	Built     string          `json:"built"`
	Files     map[string]File `json:"files"`
	Consensus []string        `json:"consensus"` // path patterns checked by fleet consensus
}

// Format is the current file format.
const Format = "nodetrust-join-reference/1"

// Load reads and checks a reference.
func Load(p string) (*Reference, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var r Reference
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("join reference %s: %w", p, err)
	}
	if r.Format != Format {
		return nil, fmt.Errorf("join reference %s: format %q, want %q", p, r.Format, Format)
	}
	for fp, f := range r.Files {
		if !path.IsAbs(fp) || path.Clean(fp) != fp {
			return nil, fmt.Errorf("join reference: %q is not a clean absolute path", fp)
		}
		for _, h := range f.SHA256 {
			if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
				return nil, fmt.Errorf("join reference: %s has a bad sha256 %q", fp, h)
			}
		}
		if len(f.SHA256) > 0 && f.Template != "" {
			return nil, fmt.Errorf("join reference: %s has both a template and hashes", fp)
		}
		for _, ph := range placeholder.FindAllString(f.Template, -1) {
			switch ph {
			case PInstanceID, PZone, PAddress, PHostname:
			default:
				return nil, fmt.Errorf("join reference: %s uses unknown placeholder %s", fp, ph)
			}
		}
	}
	for _, c := range r.Consensus {
		if !path.IsAbs(c) {
			return nil, fmt.Errorf("join reference: consensus pattern %q is not absolute", c)
		}
	}
	return &r, nil
}

// Node is what the cloud says about a worker; never what the node says.
type Node struct {
	InstanceID string
	Zone       string
	Address    string // private IPv4
}

// Hostname is the EC2 IP-based host name (ip-10-42-17-24).
func (n Node) Hostname() string { return "ip-" + strings.ReplaceAll(n.Address, ".", "-") }

// Render fills a template's placeholders for a node.
func Render(t string, n Node) string {
	return strings.NewReplacer(PInstanceID, n.InstanceID, PZone, n.Zone, PAddress, n.Address,
		PHostname, n.Hostname()).Replace(t)
}

// Expected is the accepted SHA-256 hashes (hex) of each join file on a node.
func (r *Reference) Expected(n Node) map[string][]string {
	out := make(map[string][]string, len(r.Files))
	for p, f := range r.Files {
		if len(f.SHA256) > 0 {
			out[p] = f.SHA256
			continue
		}
		s := sha256.Sum256([]byte(Render(f.Template, n)))
		out[p] = []string{hex.EncodeToString(s[:])}
	}
	return out
}

// InConsensus reports whether a path is checked by fleet consensus. A
// pattern ending in "/" covers everything below it; other patterns are
// path.Match globs.
func (r *Reference) InConsensus(p string) bool {
	for _, c := range r.Consensus {
		if strings.HasSuffix(c, "/") {
			if strings.HasPrefix(p, c) {
				return true
			}
		} else if ok, _ := path.Match(c, p); ok {
			return true
		}
	}
	return false
}

// Consensus records which hash each node reported for each consensus path,
// per AMI. It is safe for concurrent use and saved as JSON.
type Consensus struct {
	mu    sync.Mutex
	Votes map[string]map[string]map[string]*Vote `json:"votes"` // AMI -> path -> hash -> vote
}

// Vote is one hash of one path.
type Vote struct {
	First time.Time       `json:"first"` // when the fleet first reported it
	Nodes map[string]bool `json:"nodes"` // instance IDs that reported it
}

// NewConsensus starts an empty record.
func NewConsensus() *Consensus { return &Consensus{Votes: map[string]map[string]map[string]*Vote{}} }

// Observe records that a node reported hash for path.
func (c *Consensus) Observe(ami, p, hash, node string, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Votes[ami] == nil {
		c.Votes[ami] = map[string]map[string]*Vote{}
	}
	if c.Votes[ami][p] == nil {
		c.Votes[ami][p] = map[string]*Vote{}
	}
	v := c.Votes[ami][p][hash]
	if v == nil {
		v = &Vote{First: at.UTC(), Nodes: map[string]bool{}}
		c.Votes[ami][p][hash] = v
	}
	v.Nodes[node] = true
}

// Accepted is the hash accepted for a path: the one reported by at least
// two nodes and by more than half of the nodes that reported the path, or,
// with no such hash, the one the fleet saw first (trust on first use). How
// says which.
func (c *Consensus) Accepted(ami, p string) (hash, how string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hs := c.Votes[ami][p]
	if len(hs) == 0 {
		return "", "", false
	}
	all := map[string]bool{}
	for _, v := range hs {
		for n := range v.Nodes {
			all[n] = true
		}
	}
	keys := make([]string, 0, len(hs))
	for h := range hs {
		keys = append(keys, h)
	}
	sort.Slice(keys, func(i, j int) bool { // deterministic: first seen, then hash
		a, b := hs[keys[i]], hs[keys[j]]
		if !a.First.Equal(b.First) {
			return a.First.Before(b.First)
		}
		return keys[i] < keys[j]
	})
	for _, h := range keys {
		if n := len(hs[h].Nodes); n >= 2 && 2*n > len(all) { // one node agreeing with itself is not consensus
			return h, fmt.Sprintf("majority (%d of %d nodes)", len(hs[h].Nodes), len(all)), true
		}
	}
	return keys[0], fmt.Sprintf("first seen (no majority among %d nodes)", len(all)), true
}

// Forget drops a node's votes (the node left the fleet).
func (c *Consensus) Forget(node string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for ami, ps := range c.Votes {
		for p, hs := range ps {
			for h, v := range hs {
				delete(v.Nodes, node)
				if len(v.Nodes) == 0 {
					delete(hs, h)
				}
			}
			if len(hs) == 0 {
				delete(ps, p)
			}
		}
		if len(ps) == 0 {
			delete(c.Votes, ami)
		}
	}
}

// Save writes the record atomically.
func (c *Consensus) Save(p string) error {
	c.mu.Lock()
	b, err := json.MarshalIndent(c, "", "  ")
	c.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// LoadConsensus reads a saved record; a missing file is an empty record.
func LoadConsensus(p string) (*Consensus, error) {
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return NewConsensus(), nil
	}
	if err != nil {
		return nil, err
	}
	c := NewConsensus()
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("consensus %s: %w", p, err)
	}
	if c.Votes == nil {
		c.Votes = map[string]map[string]map[string]*Vote{}
	}
	return c, nil
}
