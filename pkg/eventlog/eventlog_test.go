package eventlog

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

// testdata/nitro-ami-07deef95.bin is the real event log of a NitroTPM
// instance booted from the golden AMI. The .expected.json was produced from
// tpm2_eventlog (an independent parser) and tpm2_pcrread on that instance.
func realLog(t *testing.T) (*Log, []byte, map[int][]byte, []struct {
	PCR    uint32 `json:"pcr"`
	Type   string `json:"type"`
	SHA256 string `json:"sha256"`
}) {
	t.Helper()
	raw, err := os.ReadFile("testdata/nitro-ami-07deef95.bin")
	if err != nil {
		t.Fatal(err)
	}
	l, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var exp struct {
		Events []struct {
			PCR    uint32 `json:"pcr"`
			Type   string `json:"type"`
			SHA256 string `json:"sha256"`
		} `json:"events"`
		PCRs map[string]string `json:"pcrs"`
	}
	b, _ := os.ReadFile("testdata/nitro-ami-07deef95.expected.json")
	if err := json.Unmarshal(b, &exp); err != nil {
		t.Fatal(err)
	}
	pcrs := map[int][]byte{}
	for k, v := range exp.PCRs {
		i, _ := strconv.Atoi(k)
		pcrs[i], _ = hex.DecodeString(v)
	}
	return l, raw, pcrs, exp.Events
}

func TestParseMatchesTPM2Tools(t *testing.T) {
	l, _, _, exp := realLog(t)
	if len(l.Events) != len(exp)-1 { // tpm2_eventlog also lists the header
		t.Fatalf("parsed %d events, tpm2_eventlog has %d after the header", len(l.Events), len(exp)-1)
	}
	for i, e := range l.Events {
		x := exp[i+1]
		if e.PCR != x.PCR || TypeName(e.Type) != x.Type || hex.EncodeToString(e.SHA256) != x.SHA256 {
			t.Fatalf("event %d: got PCR %d %s %x, tpm2_eventlog says PCR %d %s %s",
				e.Index, e.PCR, TypeName(e.Type), e.SHA256, x.PCR, x.Type, x.SHA256)
		}
	}
	if len(l.Algorithms) != 3 {
		t.Fatalf("algorithms %v, want SHA-256, SHA-384, SHA-512", l.Algorithms)
	}
}

func TestReplayMatchesLivePCRs(t *testing.T) {
	l, _, pcrs, _ := realLog(t)
	if err := l.CheckReplay(pcrs); err != nil {
		t.Fatal(err)
	}
}

func TestEditedLogFailsReplay(t *testing.T) {
	_, raw, pcrs, _ := realLog(t)
	// Change the kernel command line text without fixing its digest: the
	// parser accepts it, the digest check (policy) must catch it. Change a
	// digest instead: the replay catches it.
	l, _ := Parse(raw)
	for i := range l.Events {
		if l.Events[i].PCR == 4 && l.Events[i].Type == EvEFIBootServicesApp {
			l.Events[i].SHA256 = bytes.Repeat([]byte{0xaa}, 32)
			break
		}
	}
	if err := l.CheckReplay(pcrs); err == nil || !strings.Contains(err.Error(), "PCR 4") {
		t.Fatalf("edited PCR 4 event: %v", err)
	}
	// Dropping an event also breaks the replay.
	l2, _ := Parse(raw)
	for i := range l2.Events {
		if l2.Events[i].PCR == 8 {
			l2.Events = append(l2.Events[:i], l2.Events[i+1:]...)
			break
		}
	}
	if err := l2.CheckReplay(pcrs); err == nil {
		t.Fatal("log with a dropped PCR 8 event replayed")
	}
}

func TestParseRejects(t *testing.T) {
	_, raw, _, _ := realLog(t)
	for name, b := range map[string][]byte{
		"truncated": raw[:len(raw)-7],
		"no header": raw[32:],
		"empty":     nil,
	} {
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestVariablesAndBootOptions(t *testing.T) {
	l, _, _, _ := realLog(t)
	var names, descs []string
	for i := range l.Events {
		e := &l.Events[i]
		switch e.Type {
		case EvEFIVariableDriverConfig, EvEFIVariableBoot:
			v, err := e.ParseVariable()
			if err != nil {
				t.Fatal(err)
			}
			names = append(names, v.Name)
			if strings.HasPrefix(v.Name, "Boot0") {
				d, err := LoadOptionDescription(v.Data)
				if err != nil {
					t.Fatal(err)
				}
				descs = append(descs, d)
			}
		}
	}
	want := "SecureBoot PK KEK db dbx BootOrder Boot0002 Boot0000 Boot0001"
	if got := strings.Join(names, " "); got != want {
		t.Fatalf("variables %q, want %q", got, want)
	}
	if !strings.Contains(strings.Join(descs, "|"), "UEFI Amazon Elastic Block Store vol") {
		t.Fatalf("boot option descriptions %q lack the EBS root volume entry", descs)
	}
}
