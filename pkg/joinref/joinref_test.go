package joinref

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestRenderAndExpected(t *testing.T) {
	r := &Reference{Format: Format, Files: map[string]File{
		"/etc/kubernetes/nodetrust/join.yaml": {Template: "value: aws:///${AZ}/${IID}\n"},
		"/var/lib/kubelet/kubeadm-flags.env":  {Template: `ARGS="--node-ip=${IP} --hostname-override=${HOSTNAME}"` + "\n"},
		"/var/lib/kubelet/config.yaml":        {Template: "kind: KubeletConfiguration\n"},
	}}
	n := Node{InstanceID: "i-0abc", Zone: "ap-south-1c", Address: "10.42.17.24"}
	e := r.Expected(n)
	if e["/etc/kubernetes/nodetrust/join.yaml"][0] != sum("value: aws:///ap-south-1c/i-0abc\n") ||
		e["/var/lib/kubelet/kubeadm-flags.env"][0] != sum(`ARGS="--node-ip=10.42.17.24 --hostname-override=ip-10-42-17-24"`+"\n") ||
		e["/var/lib/kubelet/config.yaml"][0] != sum("kind: KubeletConfiguration\n") {
		t.Fatalf("%v", e)
	}
	// Another node gets another join.yaml hash and the same config.yaml one.
	e2 := r.Expected(Node{InstanceID: "i-0def", Zone: "ap-south-1c", Address: "10.42.20.120"})
	if e2["/etc/kubernetes/nodetrust/join.yaml"][0] == e["/etc/kubernetes/nodetrust/join.yaml"][0] ||
		e2["/var/lib/kubelet/config.yaml"][0] != e["/var/lib/kubelet/config.yaml"][0] {
		t.Fatal("per-node rendering")
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "r.json")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	if _, err := Load(write(`{"format":"nodetrust-join-reference/1","files":{"/a":{"template":"${IID}","source":"x"}},"consensus":["/opt/cni/bin/"]}`)); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]string{
		"unknown placeholder": `{"format":"nodetrust-join-reference/1","files":{"/a":{"template":"${TOKEN}"}}}`,
		"relative path":       `{"format":"nodetrust-join-reference/1","files":{"a":{"template":""}}}`,
		"other format":        `{"format":"x","files":{}}`,
		"bad hash":            `{"format":"nodetrust-join-reference/1","files":{"/a":{"sha256":["xyz"]}}}`,
		"template and hashes": `{"format":"nodetrust-join-reference/1","files":{"/a":{"template":"t","sha256":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}}}`,
		"unknown field":       `{"format":"nodetrust-join-reference/1","files":{},"extra":1}`,
	} {
		if _, err := Load(write(s)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestInConsensus(t *testing.T) {
	r := &Reference{Consensus: []string{"/opt/cni/bin/", "/etc/cni/net.d/*.conflist"}}
	for p, want := range map[string]bool{
		"/opt/cni/bin/calico": true, "/opt/cni/binx": false,
		"/etc/cni/net.d/10-calico.conflist": true, "/etc/cni/net.d/calico-kubeconfig": false,
	} {
		if r.InConsensus(p) != want {
			t.Errorf("%s: %v", p, !want)
		}
	}
}

func TestConsensus(t *testing.T) {
	t0 := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	c := NewConsensus()
	const p = "/opt/cni/bin/calico"
	// First node: trust on first use.
	c.Observe("ami-1", p, "good", "i-1", t0)
	if h, how, ok := c.Accepted("ami-1", p); !ok || h != "good" || how[:10] != "first seen" {
		t.Fatal(h, how)
	}
	// A second node with another hash: a tie, the first seen stays.
	c.Observe("ami-1", p, "evil", "i-2", t0.Add(time.Minute))
	if h, _, _ := c.Accepted("ami-1", p); h != "good" {
		t.Fatal(h)
	}
	// A third node agrees with the first: majority.
	c.Observe("ami-1", p, "good", "i-3", t0.Add(2*time.Minute))
	if h, how, _ := c.Accepted("ami-1", p); h != "good" || how[:8] != "majority" {
		t.Fatal(h, how)
	}
	// If the first node was the bad one, the majority overrules it.
	c2 := NewConsensus()
	c2.Observe("ami-1", p, "evil", "i-1", t0)
	c2.Observe("ami-1", p, "good", "i-2", t0.Add(time.Minute))
	c2.Observe("ami-1", p, "good", "i-3", t0.Add(2*time.Minute))
	if h, _, _ := c2.Accepted("ami-1", p); h != "good" {
		t.Fatal(h)
	}
	// Another AMI is counted apart.
	if _, _, ok := c.Accepted("ami-2", p); ok {
		t.Fatal("votes leaked across AMIs")
	}
	// A node that leaves takes its votes with it.
	c.Forget("i-1")
	c.Forget("i-3")
	if h, _, _ := c.Accepted("ami-1", p); h != "evil" {
		t.Fatal(h)
	}
	// Save and load.
	f := filepath.Join(t.TempDir(), "c.json")
	if err := c2.Save(f); err != nil {
		t.Fatal(err)
	}
	c3, err := LoadConsensus(f)
	if err != nil {
		t.Fatal(err)
	}
	if h, _, _ := c3.Accepted("ami-1", p); h != "good" {
		t.Fatal(h)
	}
	if c4, err := LoadConsensus(filepath.Join(t.TempDir(), "none.json")); err != nil || len(c4.Votes) != 0 {
		t.Fatal(err)
	}
}

func TestExpectedHashes(t *testing.T) {
	h1, h2 := sum("calico loopback"), sum("other")
	r := &Reference{Files: map[string]File{"/opt/cni/bin/loopback": {SHA256: []string{h1, h2}}}}
	if e := r.Expected(Node{}); len(e["/opt/cni/bin/loopback"]) != 2 || e["/opt/cni/bin/loopback"][0] != h1 {
		t.Fatal(e)
	}
}
