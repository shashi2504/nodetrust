package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Lines in the format of a worker's /proc/<pid>/mountinfo.
const hostMountinfo = `22 1 259:1 / / rw,relatime shared:1 - ext4 /dev/root rw,discard,errors=remount-ro
25 22 259:16 / /boot rw,relatime shared:4 - ext4 /dev/nvme0n1p16 rw
26 25 259:15 / /boot/efi rw,relatime shared:5 - vfat /dev/nvme0n1p15 rw,fmask=0077
27 22 0:24 / /run rw,nosuid,nodev shared:6 - tmpfs tmpfs rw,size=1580144k,mode=755
41 22 7:0 / /snap/core22/2987 ro,nodev,relatime shared:21 - squashfs /dev/loop0 ro
300 27 0:70 / /run/containerd/io.containerd.runtime.v2.task/k8s.io/abc/rootfs rw,relatime - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/3/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/3/work,uuid=on
301 22 259:1 /root/a\040b /mnt/with\040space rw - ext4 /dev/root rw
`

const containerMountinfo = `500 400 0:70 / / rw,relatime - overlay overlay rw,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/2/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/3/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/3/work
501 500 0:80 / /proc rw - proc proc rw
502 500 259:1 /var/lib/kubelet/pods/x/etc-hosts /etc/hosts rw - ext4 /dev/root rw
`

func TestParseMountinfo(t *testing.T) {
	ms, err := ParseMountinfo([]byte(hostMountinfo))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 7 {
		t.Fatalf("%d mounts", len(ms))
	}
	if m := ms[1]; m.MountPoint != "/boot" || m.Root != "/" || m.Dev != "259:16" || m.FSType != "ext4" {
		t.Fatalf("%+v", m)
	}
	o := ms[5]
	if o.FSType != "overlay" || len(o.Lower) != 2 || !strings.HasSuffix(o.Lower[1], "/1/fs") ||
		!strings.HasSuffix(o.Upper, "/3/fs") || !strings.HasSuffix(o.Work, "/3/work") {
		t.Fatalf("overlay: %+v", o)
	}
	if m := ms[6]; m.MountPoint != "/mnt/with space" || m.Root != "/root/a b" {
		t.Fatalf("escapes: %+v", m)
	}
	if _, err := ParseMountinfo([]byte("1 2 3\n")); err == nil {
		t.Fatal("accepted a malformed line")
	}
}

func TestSplitLower(t *testing.T) {
	got := splitLower(`/a:/b\:c::/data`)
	if strings.Join(got, "|") != "/a|/b:c|/data" {
		t.Fatalf("%q", got)
	}
}

// fakeProc makes <dir>/<pid>/{ns/mnt,mountinfo,comm}.
func fakeProc(t *testing.T, procs map[string][2]string) string {
	t.Helper()
	dir := t.TempDir()
	for pid, v := range procs {
		p := filepath.Join(dir, pid)
		os.MkdirAll(filepath.Join(p, "ns"), 0o755)
		os.Symlink("mnt:["+v[0]+"]", filepath.Join(p, "ns", "mnt"))
		os.WriteFile(filepath.Join(p, "mountinfo"), []byte(v[1]), 0o644)
		os.WriteFile(filepath.Join(p, "comm"), []byte("p"+pid+"\n"), 0o644)
	}
	os.MkdirAll(filepath.Join(dir, "self"), 0o755) // not a PID
	return dir
}

func TestAuditMounts(t *testing.T) {
	proc := fakeProc(t, map[string][2]string{
		"1":   {"4026531841", hostMountinfo},
		"2":   {"4026531841", hostMountinfo}, // same namespace, read once
		"900": {"4026532000", containerMountinfo},
	})
	a := AuditMounts(proc)
	if a.Errors != 0 || a.Truncated || len(a.Namespaces) != 2 {
		t.Fatalf("%+v", a)
	}
	host, ctr := a.Namespaces[0], a.Namespaces[1]
	if host.PID != 1 || host.ID != 4026531841 || host.Container || len(host.Mounts) != 7 || host.Comm != "p1" {
		t.Fatalf("host: %+v", host)
	}
	// A container namespace: only its overlay mounts are listed.
	if !ctr.Container || len(ctr.Mounts) != 1 || ctr.Mounts[0].FSType != "overlay" {
		t.Fatalf("container: %+v", ctr)
	}
}

func TestSweep(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "bin", "sub"), 0o755)
	for _, f := range []string{"bin/a", "bin/b", "bin/sub/c", "single"} {
		os.WriteFile(filepath.Join(dir, f), []byte(f), 0o644)
	}
	os.Symlink("/etc/passwd", filepath.Join(dir, "bin", "link")) // skipped
	r := Sweep([]string{filepath.Join(dir, "bin"), filepath.Join(dir, "single"), filepath.Join(dir, "missing"), "relative"}, time.Second)
	if r.Opened != 4 || r.Partial || r.Errors != 1 || !strings.Contains(r.Samples[0], "relative") {
		t.Fatalf("%+v", r)
	}
	if r := Sweep([]string{dir}, -time.Second); !r.Partial {
		t.Fatalf("budget: %+v", r)
	}
}

func TestWriteCanary(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "canary")
	if got := WriteCanary(p, []byte("0123456789abcdef0123456789abcdef")); got != "ok" {
		t.Fatal(got)
	}
	if b, _ := os.ReadFile(p); string(b) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("%q", b)
	}
}

func TestMeasurementCount(t *testing.T) {
	p := filepath.Join(t.TempDir(), "count")
	os.WriteFile(p, []byte("2664\n"), 0o444)
	if n, err := MeasurementCount(p); err != nil || n != 2664 {
		t.Fatal(n, err)
	}
}
