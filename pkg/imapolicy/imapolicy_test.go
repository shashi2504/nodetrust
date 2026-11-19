package imapolicy

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nodetrust/pkg/ima"
	"nodetrust/pkg/manifest"
)

var (
	hA    = strings.Repeat("a", 64)
	hB    = strings.Repeat("b", 64)
	empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // sha256("")
)

func testIndex() map[string]manifest.Entry {
	return map[string]manifest.Entry{
		"/usr/bin/kubelet": {Path: "/usr/bin/kubelet", Type: "file", SHA256: hA},
		"/usr/bin/whoami":  {Path: "/usr/bin/whoami", Type: "file", SHA256: hA},
		"/etc/hostname":    {Path: "/etc/hostname", Type: "file", SHA256: hA},
		"/usr/bin":         {Path: "/usr/bin", Type: "dir"},
	}
}

func testPolicy(t *testing.T) *Policy {
	p, err := LoadPolicy([]byte(`{
		"mutable": [{"pattern": "/etc/hostname", "why": "set at first boot"}],
		"runtime": [
			{"pattern": "/var/lib/kubelet/", "why": "kubelet state"},
			{"pattern": "/etc/kubernetes/*.conf", "why": "kubeadm output"},
			{"pattern": "/var/log/", "why": "logs"},
			{"pattern": "/.ismount-test-file", "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"], "why": "empty probe file"}
		]}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestClassify(t *testing.T) {
	ms := []Measurement{
		{First: 0, Count: 1, SHA256: hA, Path: "boot_aggregate"},
		{First: 1, Count: 3, SHA256: hA, Path: "/usr/bin/kubelet"},
		{First: 2, Count: 1, SHA256: hB, Path: "/usr/bin/whoami"},
		{First: 3, Count: 1, SHA256: hB, Path: "/etc/hostname"},
		{First: 4, Count: 1, SHA256: hB, Path: "/var/lib/kubelet/config.yaml"},
		{First: 5, Count: 1, SHA256: hB, Path: "/etc/kubernetes/kubelet.conf"},
		{First: 6, Count: 1, SHA256: hB, Path: "/etc/kubernetes/pki/ca.crt"},
		{First: 7, Count: 1, SHA256: hB, Path: "/usr/local/bin/evil"},
		{First: 8, Count: 1, Path: "/var/log/syslog", Violation: true},
		{First: 9, Count: 1, SHA256: hB, Path: "/usr/bin"}, // a dir in the manifest, a file here
		{First: 10, Count: 1, Path: "/usr/bin/kubelet", Violation: true},
		{First: 11, Count: 1, SHA256: empty, Path: "/.ismount-test-file"},
		{First: 12, Count: 1, SHA256: hB, Path: "/.ismount-test-file"}, // same path, not empty
	}
	r := Classify(ms, testIndex(), testPolicy(t))
	want := map[[2]string]string{}
	for k, v := range map[string]string{
		"boot_aggregate":               Aggregate,
		"/usr/bin/kubelet":             Match,
		"/usr/bin/whoami":              Mismatch,
		"/etc/hostname":                Changed,
		"/var/lib/kubelet/config.yaml": Runtime,
		"/etc/kubernetes/kubelet.conf": Runtime,
		"/etc/kubernetes/pki/ca.crt":   Unknown, // the glob does not cross directories
		"/usr/local/bin/evil":          Unknown,
		"/var/log/syslog":              Violation,
		"/usr/bin":                     Mismatch,
	} {
		want[[2]string{k, ""}] = v
	}
	want[[2]string{"/usr/bin/kubelet", "violation"}] = Unknown // no rule covers it
	want[[2]string{"/.ismount-test-file", empty}] = Runtime
	want[[2]string{"/.ismount-test-file", hB}] = Unknown // the rule only allows the empty file
	for _, it := range r.Items {
		key := [2]string{it.Path, ""}
		switch {
		case it.Violation && it.Path == "/usr/bin/kubelet":
			key[1] = "violation"
		case it.Path == "/.ismount-test-file":
			key[1] = it.SHA256
		}
		if want[key] != it.Class {
			t.Errorf("%v: class %s, want %s", key, it.Class, want[key])
		}
	}
	if r.Pass {
		t.Error("passed with a mismatch and unknowns")
	}
	if r.Counts[Unknown] != 4 || r.Counts[Mismatch] != 2 || r.Counts[Match] != 1 || r.Counts[Violation] != 1 {
		t.Errorf("counts %v", r.Counts)
	}
}

func TestCleanPasses(t *testing.T) {
	ms := []Measurement{{SHA256: hA, Path: "/usr/bin/kubelet", Count: 1}}
	if !Classify(ms, testIndex(), testPolicy(t)).Pass {
		t.Fatal("clean measurements did not pass")
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, bad := range []string{
		`{"runtime": [{"pattern": "var/lib/", "why": "x"}]}`,
		`{"runtime": [{"pattern": "/var/lib/", "why": ""}]}`,
		`{"runtime": [{"pattern": "/", "why": "everything"}]}`,
		`{"runtime": [{"pattern": "/a/[", "why": "bad glob"}]}`,
		`{"runtime": [{"pattern": "/a", "sha256": ["ABC"], "why": "bad hash"}]}`,
		`{"extra": []}`,
	} {
		if _, err := LoadPolicy([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestWithout(t *testing.T) {
	a := []Measurement{{SHA256: hA, Path: "/x"}, {SHA256: hA, Path: "/y"}}
	b := []Measurement{{SHA256: hA, Path: "/x"}, {SHA256: hB, Path: "/y"}, {SHA256: hA, Path: "/z"}}
	got := Without(b, a)
	if len(got) != 2 || got[0].Path != "/y" || got[1].Path != "/z" {
		t.Fatalf("got %+v", got)
	}
}

func TestReadSnapshot(t *testing.T) {
	dir := t.TempDir()
	body := "# format=nodetrust-ima-snapshot/1\n# pcr10_match=true\n" +
		"0\t1\t" + hA + "\tboot_aggregate\n" +
		"5\t2\t" + hB + "\t/a\\tb\\nc\\\\d\\xffe\n" +
		"7\t1\t-\t/var/log/x\n"
	name := filepath.Join(dir, "s.tsv.gz")
	f, _ := os.Create(name)
	zw := gzip.NewWriter(f)
	zw.Write([]byte(body))
	zw.Close()
	f.Close()
	s, err := ReadSnapshot(name)
	if err != nil {
		t.Fatal(err)
	}
	if s.Meta["pcr10_match"] != "true" || len(s.Measurements) != 3 {
		t.Fatalf("got %+v", s)
	}
	if p := s.Measurements[1].Path; p != "/a\tb\nc\\d\xffe" {
		t.Fatalf("unescape gave %q", p)
	}
	if !s.Measurements[2].Violation {
		t.Fatal("violation not parsed")
	}

	for _, bad := range []string{
		"0\t1\t" + hA + "\t/x\n",                                       // no format line
		"# format=nodetrust-ima-snapshot/1\n0\t1\tabc\t/x\n",           // short hash
		"# format=nodetrust-ima-snapshot/1\n0\t1\t" + hA + "\n",        // missing path
		"# format=nodetrust-ima-snapshot/1\n0\t1\t" + hA + "\t/x\\q\n", // bad escape
		"# format=nodetrust-ima-snapshot/1\n0\t1\t" + hA + "\t/x\\xz\n",
	} {
		n := filepath.Join(dir, "bad.tsv")
		os.WriteFile(n, []byte(bad), 0o644)
		if _, err := ReadSnapshot(n); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

// TestReadPythonSnapshot reads a file written by infra/phase2/node/ima_snapshot.py,
// so the two sides of the format are checked against each other.
func TestReadPythonSnapshot(t *testing.T) {
	s, err := ReadSnapshot("testdata/python-snapshot.tsv.gz")
	if err != nil {
		t.Fatal(err)
	}
	if s.Meta["pcr10_match"] != "true" || s.Meta["entries_attested"] != "4" || s.Meta["ami"] != "ami-0123456789abcdef0" {
		t.Fatalf("meta %v", s.Meta)
	}
	got := map[string]Measurement{}
	for _, m := range s.Measurements {
		got[m.Path] = m
	}
	// sha256("kubelet")
	if m := got["/usr/bin/kubelet"]; m.SHA256 != "1ca4bc7eb9b3d6f1e205da9cfab437c89d3760d0765a29a6bcbccf4ad51a2cb1" || m.First != 1 {
		t.Fatalf("kubelet %+v", m)
	}
	if !got["/var/log/syslog"].Violation {
		t.Fatal("violation lost")
	}
	if _, ok := got["/tmp/a\tb\nc\\d\xff"]; !ok {
		t.Fatalf("hostile path not round-tripped: %v", got)
	}
}

func ngEntry(pcr uint32, algo string, digest []byte, path string, violation bool) ima.Entry {
	field := func(b []byte) []byte {
		n := make([]byte, 4)
		binary.LittleEndian.PutUint32(n, uint32(len(b)))
		return append(n, b...)
	}
	d := append([]byte(algo+":\x00"), digest...)
	data := append(field(d), field(append([]byte(path), 0))...)
	e := ima.Entry{PCR: pcr, TemplateName: "ima-ng", TemplateData: data}
	if !violation {
		e.TemplateDigest = [20]byte{1}
	}
	return e
}

func TestFromLog(t *testing.T) {
	k := sha256.Sum256([]byte("kubelet"))
	es := []ima.Entry{
		ngEntry(10, "sha256", make([]byte, 32), "boot_aggregate", false),
		ngEntry(10, "sha256", k[:], "/usr/bin/kubelet", false),
		ngEntry(11, "sha256", k[:], "/other-pcr", false), // not IMA's PCR: skipped
		ngEntry(10, "sha256", make([]byte, 32), "/var/log/syslog", true),
		ngEntry(10, "sha256", k[:], "/usr/bin/kubelet", false),
	}
	ms, err := FromLog(es)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 3 || ms[1].Path != "/usr/bin/kubelet" || ms[1].Count != 2 || ms[1].First != 1 ||
		ms[1].SHA256 != hex.EncodeToString(k[:]) || !ms[2].Violation || ms[2].SHA256 != "" {
		t.Fatalf("%+v", ms)
	}
	if _, err := FromLog([]ima.Entry{ngEntry(10, "sha1", make([]byte, 20), "/x", false)}); err == nil {
		t.Fatal("sha1 digest accepted")
	}
	bad := ngEntry(10, "sha256", k[:], "/x", false)
	bad.TemplateName = "ima"
	if _, err := FromLog([]ima.Entry{bad}); err == nil {
		t.Fatal("legacy template accepted")
	}
}

// The policy the verifier service is deployed with loads, and the step 2.4
// harness paths are not in it (an attacker could hide files there).
func TestShippedPolicy(t *testing.T) {
	b, err := os.ReadFile("../../infra/phase2/runtime-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadPolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range append(p.Mutable, p.Runtime...) {
		if strings.HasPrefix(r.Pattern, "/root") || strings.Contains(r.Why, "TEST HARNESS") {
			t.Errorf("harness rule in the shipped policy: %+v", r)
		}
	}
}
