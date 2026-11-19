package ima

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// testdata/log.bin and the expected PCR 10 after each entry (log.json) were
// produced by infra/phase1/ima_replay.py, so this checks the two replays agree.
func fixture(t *testing.T) ([]byte, [][]byte) {
	t.Helper()
	log, err := os.ReadFile("testdata/log.bin")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile("testdata/log.json")
	var f struct {
		PCRAfter []string `json:"pcr_after"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	var out [][]byte
	for _, h := range f.PCRAfter {
		b, _ := hex.DecodeString(h)
		out = append(out, b)
	}
	return log, out
}

func TestReplayMatchesPython(t *testing.T) {
	log, want := fixture(t)
	entries, err := ParseLog(log)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 || !entries[2].Violation() {
		t.Fatalf("parsed %d entries", len(entries))
	}
	for n, pcr := range want {
		r, err := Replay(entries, pcr)
		if err != nil {
			t.Fatalf("prefix %d: %v", n+1, err)
		}
		if r.Attested != n+1 || r.After != len(entries)-n-1 {
			t.Fatalf("prefix %d: %+v", n+1, r)
		}
	}
	if _, err := Replay(entries, bytes.Repeat([]byte{1}, 32)); err == nil {
		t.Fatal("matched a PCR no prefix gives")
	}
}

func TestReplayCatchesEditedLog(t *testing.T) {
	log, want := fixture(t)
	edited := bytes.Replace(log, []byte("/usr/bin/kubelet"), []byte("/usr/bin/kubelex"), 1)
	entries, err := ParseLog(edited)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Replay(entries, want[len(want)-1]); err == nil {
		t.Fatal("edited log replayed to the original PCR")
	}
	// Dropping an entry also breaks the replay.
	all, _ := ParseLog(log)
	dropped := append(append([]Entry{}, all[:1]...), all[2:]...)
	if _, err := Replay(dropped, want[len(want)-1]); err == nil {
		t.Fatal("log with a dropped entry replayed")
	}
}

func TestParseLogRejects(t *testing.T) {
	log, _ := fixture(t)
	if _, err := ParseLog(log[:len(log)-3]); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated log: %v", err)
	}
}

func TestDecodeNG(t *testing.T) {
	log, _ := fixture(t)
	entries, _ := ParseLog(log)
	m, err := DecodeNG(entries[1].TemplateData)
	if err != nil {
		t.Fatal(err)
	}
	if m.Algo != "sha256" || string(m.Path) != "/usr/bin/kubelet" || len(m.Digest) != 32 {
		t.Fatalf("decoded %+v", m)
	}
}

// An incremental log: the verifier has checked the first k entries (their
// replay ended at want[k-1]) and gets the rest from byte offset Bytes.
func TestReplayFromOffset(t *testing.T) {
	log, want := fixture(t)
	all, _ := ParseLog(log)
	for k := 1; k < len(all); k++ {
		first, err := Replay(all, want[k-1])
		if err != nil || first.MatchedPrefix != k {
			t.Fatalf("prefix %d: %+v %v", k, first, err)
		}
		rest, err := ParseLog(log[first.Bytes:])
		if err != nil || len(rest) != len(all)-k {
			t.Fatalf("rest from %d: %d entries, %v", first.Bytes, len(rest), err)
		}
		r, err := ReplayFrom(rest, first.Final, want[len(want)-1])
		if err != nil || r.MatchedPrefix != len(rest) || first.Bytes+r.Bytes != int64(len(log)) {
			t.Fatalf("from %d: %+v %v", k, r, err)
		}
		// Nothing new: the start already equals the quote.
		if r, err := ReplayFrom(rest, first.Final, first.Final); err != nil || r.MatchedPrefix != 0 || r.After != len(rest) {
			t.Fatalf("no new entries: %+v %v", r, err)
		}
		// A wrong start (a log that is not the continuation) fails.
		if _, err := ReplayFrom(rest, make([]byte, 32), want[len(want)-1]); err == nil && k > 0 {
			t.Fatalf("from %d with a zero start replayed", k)
		}
	}
}
