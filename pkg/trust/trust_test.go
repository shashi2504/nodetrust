package trust

import (
	"testing"
	"time"

	"nodetrust/pkg/imapolicy"
)

func item(p, class string) imapolicy.Item {
	return imapolicy.Item{Measurement: imapolicy.Measurement{Path: p, SHA256: "ab"}, Class: class}
}

const (
	mm = imapolicy.Mismatch
	un = imapolicy.Unknown
)

func TestWeights(t *testing.T) {
	sum := 0.0
	for _, c := range Components {
		sum += c.Weight
	}
	if sum != 100 {
		t.Fatalf("weights add up to %g", sum)
	}
	if b := Score(nil); b.Score != 100 {
		t.Fatalf("clean score %g", b.Score)
	}
}

func TestComponentOf(t *testing.T) {
	for p, want := range map[string]string{
		"/usr/bin/ls":                                           Binaries,
		"/usr/local/bin/evil":                                   Binaries,
		"/usr/lib/x86_64-linux-gnu/libc.so.6":                   Binaries,
		"/usr/lib/systemd/systemd-journald":                     Binaries,
		"/opt/x/y":                                              Binaries,
		"/etc/kubernetes/kubelet.conf":                          Kubernetes,
		"/var/lib/kubelet/config.yaml":                          Kubernetes,
		"/var/lib/kubelet/sedBb5Fta":                            Kubernetes,
		"/etc/cni/net.d/10-calico.conflist":                     Kubernetes,
		"/etc/systemd/system/kubelet.service.d/10-kubeadm.conf": Kubernetes,
		"/etc/containerd/config.toml":                           Runtime,
		"/etc/containerd/certs.d/docker.io/hosts.toml":          Runtime,
		"/etc/crictl.yaml":                                      Runtime,
		"/etc/apparmor.d/usr.bin.foo":                           Security,
		"/etc/audit/rules.d/a.rules":                            Security,
		"/etc/falco/falco_rules.yaml":                           Security,
		"/etc/ssh/sshd_config":                                  SysConfig,
		"/etc/sudoers":                                          SysConfig,
		"/etc/sudoers.d/90-x":                                   SysConfig,
		"/etc/shadow":                                           SysConfig,
		"/etc/cron.d/backdoor":                                  SysConfig,
		"/var/spool/cron/crontabs/root":                         SysConfig,
		"/etc/systemd/system/evil.service":                      SysConfig,
		"/usr/lib/systemd/system/ssh.service":                   SysConfig,
		"/etc/hostname":                                         SysConfig,
	} {
		if got := ComponentOf(p); got != want {
			t.Errorf("%s: %s, want %s", p, got, want)
		}
	}
}

func TestCritical(t *testing.T) {
	for _, c := range []struct {
		it   imapolicy.Item
		typ  string
		crit bool
	}{
		{item("/usr/bin/kubelet", mm), CriticalBinary, true},
		{item("/usr/local/bin/kubelet", un), CriticalBinary, true}, // a copy elsewhere
		{item("/usr/bin/containerd", mm), CriticalBinary, true},
		{item("/usr/bin/containerd-shim-runc-v2", mm), CriticalBinary, true},
		{item("/usr/sbin/runc", mm), CriticalBinary, true},
		{item("/usr/local/bin/nodetrust-agent", mm), CriticalBinary, true},
		{item("/usr/bin/falco", mm), CriticalBinary, true},
		{item("/usr/bin/kubelet", imapolicy.Match), "", false},
		{item("/boot/vmlinuz-9.9", un), CriticalBootFile, true},
		{item("/boot/efi/EFI/ubuntu/grubx64.efi", mm), CriticalBootFile, true},
		{item("/boot/grub/grubenv", imapolicy.Changed), "", false}, // allowed mutable file
		{item("/usr/lib/modules/7.0.0-1017-aws/kernel/evil.ko.zst", un), CriticalModule, true},
		{item("/etc/ld.so.preload", un), CriticalPreload, true},
		{item("/etc/ld.so.preload", imapolicy.Runtime), CriticalPreload, true},
		{item(IMAPolicyPath, mm), CriticalIMA, true},
		{item("/usr/bin/ls", mm), "", false},
		{item("/etc/kubernetes/kubelet.conf", imapolicy.Runtime), "", false},
	} {
		f, ok := Critical(c.it)
		if ok != c.crit || f.Type != c.typ {
			t.Errorf("%s %s: %v %q, want %v %q", c.it.Class, c.it.Path, ok, f.Type, c.crit, c.typ)
		}
	}
}

// The scenarios of blueprint 12.1 whose expected scores are in Section 7.3.
func TestScenarioScores(t *testing.T) {
	for _, c := range []struct {
		name  string
		items []imapolicy.Item
		score float64
		tier  string
		crit  string
	}{
		{"clean", nil, 100, Healthy, ""},
		{"A1 kubelet replaced", []imapolicy.Item{item("/usr/bin/kubelet", mm)}, 100, Healthy, CriticalBinary},
		{"A2 containerd replaced", []imapolicy.Item{item("/usr/bin/containerd", mm)}, 100, Healthy, CriticalBinary},
		{"A3 falco replaced", []imapolicy.Item{item("/usr/bin/falco", mm)}, 100, Healthy, CriticalBinary},
		{"A7 staged kernel", []imapolicy.Item{item("/boot/vmlinuz-6.0.0-evil", un)}, 100, Healthy, CriticalBootFile},
		{"A8 system binary replaced", []imapolicy.Item{item("/usr/bin/ls", mm)}, 90, Warning, ""},
		{"A9 unknown binary", []imapolicy.Item{item("/usr/local/bin/evil", un)}, 90, Warning, ""},
		{"A10 kubelet and containerd config", []imapolicy.Item{
			item("/var/lib/kubelet/config.yaml", mm), item("/etc/containerd/config.toml", mm)}, 72.5, Degraded, ""},
		{"A11 four system config files", []imapolicy.Item{
			item("/etc/ssh/sshd_config", mm), item("/etc/sudoers", mm),
			item("/etc/cron.d/e2scrub_all", mm), item("/etc/systemd/system/x.service", un)}, 80, Warning, ""},
		{"A13 runc replaced", []imapolicy.Item{item("/usr/sbin/runc", mm)}, 100, Healthy, CriticalBinary},
		{"same file twice counts once", []imapolicy.Item{item("/usr/bin/ls", mm), item("/usr/bin/ls", mm)}, 90, Warning, ""},
		{"three binaries empty the component", []imapolicy.Item{
			item("/usr/bin/a", mm), item("/usr/bin/b", mm), item("/usr/bin/c", un), item("/usr/bin/d", un)}, 70, Degraded, ""},
		{"untrusted by score", []imapolicy.Item{
			item("/usr/bin/a", mm), item("/usr/bin/b", mm), item("/usr/bin/c", mm),
			item("/etc/kubernetes/a", mm), item("/etc/kubernetes/b", mm)}, 45, Untrusted, ""},
		{"allowed classes do not count", []imapolicy.Item{
			item("/var/lib/kubelet/pki/kubelet.crt", imapolicy.Runtime), item("/boot/grub/grubenv", imapolicy.Changed),
			item("/var/log/syslog", imapolicy.Violation), item("/usr/bin/ls", imapolicy.Match)}, 100, Healthy, ""},
	} {
		crit, files := Assess(c.items)
		b := Score(files)
		if b.Score != c.score || TierOf(b.Score) != c.tier {
			t.Errorf("%s: score %g %s, want %g %s (%s)", c.name, b.Score, TierOf(b.Score), c.score, c.tier, b.Summary())
		}
		got := ""
		if len(crit) > 0 {
			got = crit[0].Type
		}
		if got != c.crit {
			t.Errorf("%s: critical %q, want %q", c.name, got, c.crit)
		}
	}
}

func TestTierBoundaries(t *testing.T) {
	for s, want := range map[float64]string{100: Healthy, 90.5: Healthy, 90: Warning, 75: Warning, 74.99: Degraded, 50: Degraded, 49.9: Untrusted, 0: Untrusted} {
		if got := TierOf(s); got != want {
			t.Errorf("%g: %s, want %s", s, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	t0 := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	min := func(m int) time.Time { return t0.Add(time.Duration(m) * time.Minute) }
	// A10: -27.5 in one cycle.
	if got := Classify(nil, min(5), 27.5); got != Sudden {
		t.Fatalf("A10: %s", got)
	}
	// A8: one drop of 10.
	if got := Classify(nil, min(5), 10); got != Isolated {
		t.Fatalf("A8: %s", got)
	}
	// A11: four drops of 5, one every 5 minutes (however many cycles that is).
	var ds []Drop
	want := []string{Isolated, Unclassified, Gradual, Gradual}
	for i, w := range want {
		at := min(i * 5)
		got := Classify(ds, at, 5)
		if got != w {
			t.Fatalf("A11 drop %d: %s, want %s", i+1, got, w)
		}
		ds = append(ds, Drop{At: at, Size: 5, Class: got})
	}
	// Drops older than 30 minutes do not count.
	old := []Drop{{At: min(0), Size: 5}, {At: min(10), Size: 5}}
	if got := Classify(old, min(45), 5); got != Isolated {
		t.Fatalf("window: %s", got)
	}
	// Three drops adding up to less than 10 are not gradual.
	small := []Drop{{At: min(1), Size: 2}, {At: min(2), Size: 2}}
	if got := Classify(small, min(3), 2); got != Unclassified {
		t.Fatalf("small: %s", got)
	}
}
