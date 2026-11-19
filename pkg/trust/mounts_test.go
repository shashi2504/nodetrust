package trust

import (
	"strings"
	"testing"

	"nodetrust/pkg/protocol"
)

const snap = SnapshotterRoot

func hostNS(extra ...protocol.Mount) protocol.MountNamespace {
	ms := []protocol.Mount{
		{MountPoint: "/", Root: "/", Dev: "259:1", FSType: "ext4"},
		{MountPoint: "/boot", Root: "/", Dev: "259:16", FSType: "ext4"},
		{MountPoint: "/boot/efi", Root: "/", Dev: "259:15", FSType: "vfat"},
		{MountPoint: "/run", Root: "/", Dev: "0:24", FSType: "tmpfs"},
		{MountPoint: "/snap/core22/2987", Root: "/", Dev: "7:0", FSType: "squashfs"},
		{MountPoint: "/run/containerd/io.containerd.runtime.v2.task/k8s.io/a/rootfs", FSType: "overlay",
			Lower: []string{snap + "/2/fs", snap + "/1/fs"}, Upper: snap + "/3/fs", Work: snap + "/3/work"},
	}
	return protocol.MountNamespace{ID: 1, PID: 1, Comm: "systemd", Mounts: append(ms, extra...)}
}

func audit(ns ...protocol.MountNamespace) *protocol.MountAudit {
	return &protocol.MountAudit{Namespaces: ns}
}

func types(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.Type+" "+f.Path)
	}
	return strings.Join(s, "; ")
}

func TestMountsClean(t *testing.T) {
	// A systemd service with ProtectSystem=strict: read-only views of the
	// host's own directories, and a private /tmp.
	svc := protocol.MountNamespace{ID: 2, PID: 300, Comm: "systemd-resolve", Mounts: []protocol.Mount{
		{MountPoint: "/", Root: "/", Dev: "259:1", FSType: "ext4"},
		{MountPoint: "/usr", Root: "/usr", Dev: "259:1", FSType: "ext4"},
		{MountPoint: "/etc", Root: "/etc", Dev: "259:1", FSType: "ext4"},
		{MountPoint: "/boot", Root: "/", Dev: "259:16", FSType: "ext4"},
		{MountPoint: "/boot/efi/EFI", Root: "/EFI", Dev: "259:15", FSType: "vfat"},
		{MountPoint: "/tmp", Root: "/systemd-private-x/tmp", Dev: "259:1", FSType: "ext4"},
		// ProtectKernelModules=yes, as seen on a worker
		{MountPoint: "/usr/lib/modules", Root: "/systemd/inaccessible/dir", Dev: "0:24", FSType: "tmpfs"},
	}}
	// A container: its own files, bind mounts inside it are its business.
	ctr := protocol.MountNamespace{ID: 3, PID: 900, Comm: "pause", Container: true, Mounts: []protocol.Mount{
		{MountPoint: "/", FSType: "overlay", Lower: []string{"12/fs", "11/fs"}, Upper: snap + "/13/fs", Work: snap + "/13/work"},
	}}
	if f := CheckMounts(audit(hostNS(), svc, ctr)); len(f) != 0 {
		t.Fatalf("clean node: %s", types(f))
	}
}

func TestMountsAttacks(t *testing.T) {
	for name, c := range map[string]struct {
		a    *protocol.MountAudit
		want string
	}{
		"A15 overlay over /usr/bin": {audit(hostNS(protocol.Mount{MountPoint: "/usr/bin", FSType: "overlay",
			Lower: []string{"/usr/bin"}, Upper: "/root/up", Work: "/root/work"})), CriticalOverlay + " /usr/bin"},
		"overlay in a private namespace": {audit(hostNS(), protocol.MountNamespace{ID: 9, PID: 4242, Container: true,
			Mounts: []protocol.Mount{{MountPoint: "/", FSType: "overlay", Lower: []string{"/opt/x"}, Upper: "/opt/u", Work: "/opt/w"}}}),
			CriticalOverlay + " /"},
		"overlay escaping with ..": {audit(hostNS(protocol.Mount{MountPoint: "/mnt", FSType: "overlay",
			Lower: []string{snap + "/../../../../../root/x"}, Upper: snap + "/5/fs", Work: snap + "/5/work"})), CriticalOverlay},
		"bind over kubelet": {audit(hostNS(protocol.Mount{MountPoint: "/usr/bin/kubelet", Root: "/root/clean-kubelet",
			Dev: "259:1", FSType: "ext4"})), CriticalBind + " /usr/bin/kubelet"},
		"tmpfs over /etc/kubernetes": {audit(hostNS(protocol.Mount{MountPoint: "/etc/kubernetes", Root: "/", Dev: "0:99",
			FSType: "tmpfs"})), CriticalBind + " /etc/kubernetes"},
		"tmpfs over /etc hides watched files": {audit(hostNS(protocol.Mount{MountPoint: "/etc", Root: "/", Dev: "0:99",
			FSType: "tmpfs"})), CriticalBind + " /etc"},
		"a second mount stacked on /boot": {audit(hostNS(protocol.Mount{MountPoint: "/boot", Root: "/", Dev: "0:99",
			FSType: "tmpfs"})), CriticalBind + " /boot"},
		"bind in a private namespace": {audit(hostNS(), protocol.MountNamespace{ID: 9, PID: 4242, Comm: "sh", Mounts: []protocol.Mount{
			{MountPoint: "/", Root: "/", Dev: "259:1", FSType: "ext4"},
			{MountPoint: "/usr/sbin", Root: "/var/tmp/x", Dev: "259:1", FSType: "ext4"}}}), CriticalBind + " /usr/sbin"},
		"inaccessible node over /usr/bin": {audit(hostNS(), protocol.MountNamespace{ID: 9, PID: 4242, Comm: "x", Mounts: []protocol.Mount{
			{MountPoint: "/", Root: "/", Dev: "259:1", FSType: "ext4"},
			{MountPoint: "/usr/bin", Root: "/systemd/inaccessible/dir", Dev: "0:24", FSType: "tmpfs"}}}), CriticalBind + " /usr/bin"},
		"fake inaccessible node from another tmpfs": {audit(hostNS(), protocol.MountNamespace{ID: 9, PID: 4242, Comm: "x", Mounts: []protocol.Mount{
			{MountPoint: "/", Root: "/", Dev: "259:1", FSType: "ext4"},
			{MountPoint: "/usr/lib/modules", Root: "/systemd/inaccessible/dir", Dev: "0:99", FSType: "tmpfs"}}}), CriticalBind + " /usr/lib/modules"},
		"no host namespace": {audit(protocol.MountNamespace{ID: 5, PID: 77}), CriticalAudit},
		"no audit":          {nil, CriticalAudit},
		"truncated":         {&protocol.MountAudit{Truncated: true, Namespaces: []protocol.MountNamespace{hostNS()}}, CriticalAudit},
	} {
		f := CheckMounts(c.a)
		if !strings.Contains(types(f), c.want) {
			t.Errorf("%s: %q, want %q", name, types(f), c.want)
		}
	}
}
