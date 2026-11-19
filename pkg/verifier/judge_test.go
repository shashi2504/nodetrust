package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"

	"nodetrust/pkg/bootpolicy"
	"nodetrust/pkg/eventlog"
	"nodetrust/pkg/ima"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/manifest"
	"nodetrust/pkg/protocol"
	"nodetrust/pkg/trust"
)

func hexsum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// judgeFixture: the real NitroTPM boot of ami-07deef95f949d1d5d with its
// quoted PCRs, a manifest holding the boot files and two IMA paths, and an
// IMA log that matches it.
func judgeFixture(t *testing.T) (*QuoteResult, Worker, *manifest.Trusted, *imapolicy.Policy, *bootpolicy.Policy) {
	t.Helper()
	raw, err := os.ReadFile("../eventlog/testdata/nitro-ami-07deef95.bin")
	if err != nil {
		t.Fatal(err)
	}
	l, err := eventlog.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	var exp struct {
		PCRs map[string]string `json:"pcrs"`
	}
	b, _ := os.ReadFile("../eventlog/testdata/nitro-ami-07deef95.expected.json")
	json.Unmarshal(b, &exp)
	pcrs := map[int][]byte{}
	for k, v := range exp.PCRs {
		i, _ := strconv.Atoi(k)
		pcrs[i], _ = hex.DecodeString(v)
	}
	const ami = "ami-07deef95f949d1d5d"
	bp, err := bootpolicy.Reference(nil, l, ami, "test")
	if err != nil {
		t.Fatal(err)
	}
	idx := map[string]manifest.Entry{}
	add := func(p, sha, ac string) { idx[p] = manifest.Entry{Path: p, Type: "file", SHA256: sha, Authenticode: ac} }
	add("/boot/efi/EFI/BOOT/BOOTX64.EFI", "6fe6e1bcbe6cf6baec8e056d40361ca1aa715cc04ddcc2855351de060b84350b", "724de6844dd0fe618ba5776c7bca0728be38a6544e24e44ef259b987b7abce80")
	add("/boot/efi/EFI/ubuntu/grubx64.efi", "a831af01e4fb5e3c9457120e1d08ea13d98a0a47b62728c284b7f502d535965c", "4caffb530989433f184353c48d8150fcdce6037933ab129249f50f0068cf1815")
	add("/boot/vmlinuz-7.0.0-1017-aws", "cab0d1e698f1840109aff4fb2a00c3bc3fb304aa48098773a9b81b3cb3996e6e", "43fe96482536d1048bf3a3cb4bf306fb22f7cd12f26950d5185bb18fb3039d1e")
	add("/boot/grub/grub.cfg", "03a187d017483a99f19ba973a486a3c8d9aad52d16d5c6c38d38056fda73dae4", "")
	add("/boot/efi/EFI/ubuntu/grub.cfg", "01a550946685e21e873121bc2d23b089eabd833945ea78c6ed554e97d4c2c3ed", "")
	for p, h := range map[string]string{"command.lst": "aef695413d1a1b9eaff753a15512d0ba79e23e5524033eec20c7a1c7c20eb1c4",
		"fs.lst": "32fc7f5de8c0a5dc0b1e7eb609ca31a77eb3475539e1d97a4543dca1b9b26c57", "crypto.lst": "1b766f38a94927fe9b7bc1e809f0363e778e14c601e800faea271a2e75d3fc43",
		"terminal.lst": "46f888c52f36baf9b62d60bc8d06426a314aad5a0ff86a4362a91c2512a1df9c", "bli.mod": "b49a7fd5edc02f168f0de51309313278dc2347c0f83a5cbedcb8974790a5e7e8"} {
		add("/boot/grub/x86_64-efi/"+p, h, "")
	}
	add("/boot/microcode.cpio", "85548ac86ecc5dbd1b587062d765e298a074ac972d88d0e6a0c918d7ffbf145b", "")
	add("/usr/bin/kubelet", hexsum("kubelet"), "")
	add("/usr/local/bin/nodetrust-agent", hexsum("agent"), "")

	entries, _ := ima.ParseLog(imaLog([][2]string{{"boot_aggregate", "a"}, {"/usr/bin/kubelet", "kubelet"}, {"/usr/local/bin/nodetrust-agent", "agent"}}))
	q := &QuoteResult{IMAEntries: entries, PCRs: pcrs, BootLog: l}
	w := Worker{InstanceID: "i-1", AMI: ami, RootVolumeID: "vol-0af96f3cd779bc1e4"}
	return q, w, &manifest.Trusted{Index: idx}, &imapolicy.Policy{}, bp
}

func TestJudgeTrusted(t *testing.T) {
	q, w, tr, rt, bp := judgeFixture(t)
	v := Judge(q, w, tr, rt, bp, nil)
	if !v.Clean || v.Boot != "pass" || v.IMA[imapolicy.Match] != 2 || v.Initrd != "/boot/microcode.cpio" {
		t.Fatalf("%+v", v)
	}
	t.Log(v.Summary())
}

func TestJudgeFindings(t *testing.T) {
	cases := map[string]struct {
		edit func(q *QuoteResult, w *Worker, tr *manifest.Trusted, bp **bootpolicy.Policy)
		want string
	}{
		"unknown binary ran": {func(q *QuoteResult, _ *Worker, _ *manifest.Trusted, _ **bootpolicy.Policy) {
			more, _ := ima.ParseLog(imaLog([][2]string{{"/tmp/miner", "x"}}))
			q.IMAEntries = append(q.IMAEntries, more...)
		}, "unknown /tmp/miner (system-binaries)"},
		"kubelet replaced": {func(q *QuoteResult, _ *Worker, _ *manifest.Trusted, _ **bootpolicy.Policy) {
			q.IMAEntries, _ = ima.ParseLog(imaLog([][2]string{{"/usr/bin/kubelet", "evil"}}))
		}, "critical critical-binary /usr/bin/kubelet"},
		"boot log presented for another instance": {func(_ *QuoteResult, w *Worker, _ *manifest.Trusted, _ **bootpolicy.Policy) {
			w.RootVolumeID = "vol-0123456789abcdef0"
		}, "root-volume"},
		"no boot log": {func(q *QuoteResult, _ *Worker, _ *manifest.Trusted, _ **bootpolicy.Policy) {
			q.BootLog = nil
		}, "no boot event log"},
		"kernel not in this AMI's manifest": {func(_ *QuoteResult, _ *Worker, tr *manifest.Trusted, _ **bootpolicy.Policy) {
			delete(tr.Index, "/boot/vmlinuz-7.0.0-1017-aws")
		}, "efi-application"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			q, w, tr, rt, bp := judgeFixture(t)
			c.edit(q, &w, tr, &bp)
			v := Judge(q, w, tr, rt, bp, nil)
			if v.Clean || !strings.Contains(v.Summary(), c.want) {
				t.Fatalf("want %q in %q", c.want, v.Summary())
			}
		})
	}
}

func TestJudgeCanary(t *testing.T) {
	canary := []byte("0123456789abcdef0123456789abcdef")
	q, w, tr, rt, bp := judgeFixture(t)
	q.Canary = canary
	if v := Judge(q, w, tr, rt, bp, nil); v.Canary != "missing" || len(v.Critical) != 1 || v.Critical[0].Type != trust.CriticalCanary {
		t.Fatalf("no canary entry: %+v", v)
	}
	more, _ := ima.ParseLog(imaLog([][2]string{{protocol.CanaryPath, string(canary)}}))
	q.IMAEntries = append(q.IMAEntries, more...)
	rt.Runtime = []imapolicy.Rule{{Pattern: "/var/lib/nodetrust/", Why: "agent state"}}
	if v := Judge(q, w, tr, rt, bp, nil); v.Canary != "found" || !v.Clean {
		t.Fatalf("canary entry present: %+v", v)
	}
	// An old canary value does not count.
	q.Canary = []byte("ffffffffffffffffffffffffffffffff")
	if v := Judge(q, w, tr, rt, bp, nil); v.Canary != "missing" {
		t.Fatalf("stale canary accepted: %+v", v)
	}
}

func TestJudgeIncrementalBoot(t *testing.T) {
	q, w, tr, rt, bp := judgeFixture(t)
	q.BootLog = nil
	q.Next = ReplayState{Valid: true, BootPCRs: map[int][]byte{0: {1}}}
	if v := Judge(q, w, tr, rt, bp, nil); v.Boot != "unchanged" || !v.Clean {
		t.Fatalf("incremental: %+v", v)
	}
	q.BootChanged = true
	if v := Judge(q, w, tr, rt, bp, nil); v.Boot != "fail" || v.Critical[0].Type != trust.CriticalBoot {
		t.Fatalf("boot PCRs changed: %+v", v)
	}
}

func TestJudgeMounts(t *testing.T) {
	q, w, tr, rt, bp := judgeFixture(t)
	q.MountsAsked = true // and none sent
	if v := Judge(q, w, tr, rt, bp, nil); len(v.Critical) != 1 || v.Critical[0].Type != trust.CriticalAudit {
		t.Fatalf("%+v", v)
	}
}
