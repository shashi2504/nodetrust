package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"nodetrust/pkg/eventlog"
	"nodetrust/pkg/ima"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/nodetrust"
	"nodetrust/pkg/trust"
)

// demo runs the verifier's checks offline, on saved logs and made-up
// measurements, so they can be shown without AWS or a TPM
// ("verifier demo [-repo .]"). Part 1 replays a real NitroTPM boot event
// log (from the golden AMI) to PCRs 0-9 and shows that one changed digest
// no longer matches. Part 2 replays an IMA log to the quoted PCR 10 and
// catches an edited entry. Part 3 scores example changes with the trust
// engine (blueprint 7.2, 7.3). Part 4 classifies four small edits five
// minutes apart as drift (7.4). Part 5 signs and checks a NodeTrust update
// and refuses an edited, replayed, moved, foreign or stale copy (8.1).
// It exits 1 if any result is not the expected one.
func demo(args []string) int {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	repo := fs.String("repo", ".", "repository root (for the saved logs in pkg/*/testdata)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	d := &demoRun{}
	d.bootLog(filepath.Join(*repo, "pkg/eventlog/testdata/nitro-ami-07deef95.bin"))
	d.imaLog(filepath.Join(*repo, "pkg/ima/testdata"))
	d.scoring()
	d.drift()
	d.signed()
	fmt.Printf("\ndemo: %d checks, %d not as expected\n", d.n, d.bad)
	if d.bad > 0 {
		return 1
	}
	return 0
}

type demoRun struct{ n, bad int }

// expect prints one result line; ok says whether it is the expected one.
func (d *demoRun) expect(ok bool, format string, a ...any) {
	d.n++
	mark := "ok  "
	if !ok {
		mark = "BAD "
		d.bad++
	}
	fmt.Printf("  %s %s\n", mark, fmt.Sprintf(format, a...))
}

func (d *demoRun) bootLog(path string) {
	fmt.Println("1. boot event log (pkg/eventlog)")
	b, err := os.ReadFile(path)
	if err != nil {
		d.expect(false, "read %s: %v", path, err)
		return
	}
	l, err := eventlog.Parse(b)
	if err != nil {
		d.expect(false, "parse: %v", err)
		return
	}
	pcrs := l.Replay()
	quoted := map[int][]byte{}
	for i := 0; i <= 9; i++ {
		quoted[i] = pcrs[uint32(i)]
		if quoted[i] == nil {
			quoted[i] = make([]byte, 32)
		}
	}
	fmt.Printf("     %d events; PCR 0 %x…  PCR 4 %x…  PCR 7 %x…\n", len(l.Events), quoted[0][:8], quoted[4][:8], quoted[7][:8])
	d.expect(l.CheckReplay(quoted) == nil, "the log replays to the quoted PCRs 0-9")
	// Change the digest of the first event in PCR 4 (the boot loader).
	for i := range l.Events {
		if l.Events[i].PCR == 4 && l.Events[i].Type != eventlog.EvNoAction {
			l.Events[i].SHA256 = append([]byte{}, l.Events[i].SHA256...)
			l.Events[i].SHA256[0] ^= 1
			fmt.Printf("     changed event %d (%s) in PCR 4\n", l.Events[i].Index, eventlog.TypeName(l.Events[i].Type))
			break
		}
	}
	err = l.CheckReplay(quoted)
	d.expect(err != nil, "the edited log is refused: %v", short(err))
}

func (d *demoRun) imaLog(dir string) {
	fmt.Println("\n2. IMA log (pkg/ima)")
	b, err := os.ReadFile(filepath.Join(dir, "log.bin"))
	if err != nil {
		d.expect(false, "read: %v", err)
		return
	}
	var want struct {
		PCRAfter []string `json:"pcr_after"`
	}
	j, err := os.ReadFile(filepath.Join(dir, "log.json"))
	if err == nil {
		err = json.Unmarshal(j, &want)
	}
	if err != nil || len(want.PCRAfter) == 0 {
		d.expect(false, "read log.json: %v", err)
		return
	}
	entries, err := ima.ParseLog(b)
	if err != nil {
		d.expect(false, "parse: %v", err)
		return
	}
	for _, e := range entries {
		if m, err := ima.DecodeNG(e.TemplateData); err == nil {
			fmt.Printf("     %-10s %s\n", e.TemplateName, m.Path)
		}
	}
	quoted, _ := hex.DecodeString(want.PCRAfter[len(want.PCRAfter)-1])
	r, err := ima.Replay(entries, quoted)
	d.expect(err == nil && r.Attested == len(entries), "all %d entries replay to the quoted PCR 10", len(entries))
	// Edit the data of the last entry, as someone hiding a file would.
	last := &entries[len(entries)-1]
	last.TemplateData = append([]byte{}, last.TemplateData...)
	last.TemplateData[len(last.TemplateData)-1] ^= 1
	_, err = ima.Replay(entries, quoted)
	d.expect(err != nil, "the edited log is refused: %v", short(err))
}

func (d *demoRun) scoring() {
	fmt.Println("\n3. trust engine (pkg/trust): score = sum of w * max(0, 1 - m/t)")
	for _, c := range trust.Components {
		fmt.Printf("     %-18s weight %2.0f  tolerance %d\n", c.Name, c.Weight, c.Tolerance)
	}
	mm, un := imapolicy.Mismatch, imapolicy.Unknown
	cases := []struct {
		name     string
		items    [][2]string // path, class
		score    float64
		tier     string
		critical bool
	}{
		{"clean node", nil, 100, trust.Healthy, false},
		{"unknown binary run", [][2]string{{"/usr/local/bin/x", un}}, 90, trust.Warning, false},
		{"sshd_config edited", [][2]string{{"/etc/ssh/sshd_config", mm}}, 95, trust.Healthy, false},
		{"kubelet config edited", [][2]string{{"/var/lib/kubelet/config.yaml", mm}}, 87.5, trust.Warning, false},
		{"containerd config edited", [][2]string{{"/etc/containerd/config.toml", mm}}, 85, trust.Warning, false},
		{"three binaries replaced", [][2]string{{"/usr/bin/a", mm}, {"/usr/bin/b", mm}, {"/usr/bin/c", mm}}, 70, trust.Degraded, false},
		{"kubelet binary replaced", [][2]string{{"/usr/bin/kubelet", mm}}, 100, trust.Healthy, true},
		{"unknown kernel module", [][2]string{{"/usr/lib/modules/6.8.0/extra/rk.ko", un}}, 100, trust.Healthy, true},
	}
	for _, c := range cases {
		var items []imapolicy.Item
		for _, it := range c.items {
			items = append(items, imapolicy.Item{Measurement: imapolicy.Measurement{Path: it[0], SHA256: "ab"}, Class: it[1]})
		}
		crit, files := trust.Assess(items)
		b := trust.Score(files)
		tier := trust.TierOf(b.Score)
		got := fmt.Sprintf("%5.1f %-9s", b.Score, tier)
		if len(crit) > 0 {
			got = "critical: " + crit[0].Type
		}
		d.expect(b.Score == c.score && tier == c.tier && (len(crit) > 0) == c.critical, "%-26s -> %s", c.name, got)
	}
}

func (d *demoRun) drift() {
	fmt.Println("\n4. drift (pkg/trust): four config edits, one every 5 minutes")
	t0 := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	var drops []trust.Drop
	var files []trust.File
	prev := 100.0
	want := []string{trust.Isolated, trust.Unclassified, trust.Gradual, trust.Gradual}
	for i, p := range []string{"/etc/ssh/sshd_config", "/etc/sudoers", "/etc/cron.d/x", "/etc/systemd/system/x.service"} {
		at := t0.Add(time.Duration(i*5) * time.Minute)
		files = append(files, trust.File{Path: p, Class: imapolicy.Mismatch, Component: trust.ComponentOf(p)})
		s := trust.Score(files).Score
		cls := trust.Classify(drops, at, prev-s)
		drops = append(drops, trust.Drop{At: at, Size: prev - s, Class: cls})
		d.expect(cls == want[i], "%s %-30s %5.1f -> %5.1f  %s", at.Format("15:04"), p, prev, s, cls)
		prev = s
	}
}

func (d *demoRun) signed() {
	fmt.Println("\n5. signed NodeTrust update (pkg/nodetrust)")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	id, _ := nodetrust.KeyID(&key.PublicKey)
	now := time.Now().UTC()
	st := &nodetrust.State{InstanceID: "i-0123456789abcdef0", AMI: "ami-034d8e94160b0fecb", Seq: 42,
		IssuedAt: now, Tier: trust.Warning, Score: 90, State: "verified"}
	s, err := nodetrust.Sign(key, st)
	if err != nil {
		d.expect(false, "sign: %v", err)
		return
	}
	fmt.Printf("     key %s; payload %d bytes\n", id, len(s.Payload))
	_, err = nodetrust.Check(&key.PublicKey, s, st.InstanceID, 41, now, 5*time.Minute)
	d.expect(err == nil, "the update verifies (signature, instance, seq 42 after 41, fresh)")

	// The same values, edited to look healthy.
	raw, _ := base64.StdEncoding.DecodeString(s.Payload)
	var p map[string]any
	_ = json.Unmarshal(raw, &p)
	p["tier"], p["score"] = trust.Healthy, 100
	edited, _ := json.Marshal(p)
	t := *s
	t.Payload = base64.StdEncoding.EncodeToString(edited)
	_, err = nodetrust.Check(&key.PublicKey, &t, st.InstanceID, 41, now, 5*time.Minute)
	d.expect(err != nil, "edited to healthy 100: %v", short(err))

	_, err = nodetrust.Check(&key.PublicKey, s, st.InstanceID, 42, now, 5*time.Minute)
	d.expect(err != nil, "replayed (reader already has seq 42): %v", short(err))

	_, err = nodetrust.Check(&key.PublicKey, s, "i-0fedcba9876543210", 0, now, 5*time.Minute)
	d.expect(err != nil, "copied to another node's object: %v", short(err))

	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f, _ := nodetrust.Sign(other, st)
	_, err = nodetrust.Check(&key.PublicKey, f, st.InstanceID, 41, now, 5*time.Minute)
	d.expect(err != nil, "signed with another key: %v", short(err))

	_, err = nodetrust.Check(&key.PublicKey, s, st.InstanceID, 41, now.Add(10*time.Minute), 5*time.Minute)
	d.expect(err != nil, "read 10 minutes later: %v", short(err))
}

func short(err error) string {
	if err == nil {
		return "no error"
	}
	s := err.Error()
	if len(s) > 90 {
		s = s[:90] + "…"
	}
	return s
}
