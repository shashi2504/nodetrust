package trust

import (
	"fmt"
	"path"
	"strings"

	"nodetrust/pkg/protocol"
)

// More critical finding types (blueprint 7.2, 10.3).
const (
	CriticalCanary  = "ima-canary"    // the canary is not in the quoted IMA log: IMA stopped recording
	CriticalOverlay = "mount-overlay" // an overlay mount outside containerd's snapshotter tree
	CriticalBind    = "mount-bind"    // a mount over a watched path that does not show the host's own files
	CriticalAudit   = "mount-audit"   // the audit is missing, truncated or cannot see the host namespace
)

// SnapshotterRoot is where containerd's overlay snapshotter keeps layers.
const SnapshotterRoot = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"

// WatchedPaths are host paths a mount must not hide or replace (blueprint
// 10.2, 10.3): the binaries, boot files and configs the score and the
// critical set rely on. A mount at, under or above one of them (other than
// "/") is checked.
var WatchedPaths = []string{
	"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/boot", "/opt/cni/bin",
	"/etc/kubernetes", "/etc/containerd", "/etc/cni", "/etc/systemd", "/etc/ssh",
	"/etc/sudoers", "/etc/sudoers.d", "/etc/passwd", "/etc/shadow", "/etc/group",
	"/etc/crontab", "/etc/cron.d", "/etc/ld.so.preload", "/etc/ld.so.conf.d",
	"/etc/pam.d", "/etc/apparmor.d", "/etc/nodetrust", "/var/lib/kubelet/config.yaml",
}

// baseMounts are the host mounts the golden AMI has at watched paths.
var baseMounts = map[string]bool{"/": true, "/boot": true, "/boot/efi": true}

// hiddenOK are the watched paths a systemd service may hide with an
// "inaccessible" node: ProtectKernelModules=yes does this to the kernel
// module directories in the namespaces of many services (the agent's
// included; seen on a worker, 2026-11-19). Hiding modules changes nothing
// the verifier relies on: the kernel measures a module when it loads it,
// and modules are locked after boot.
var hiddenOK = []string{"/usr/lib/modules", "/lib/modules"}

// inaccessible reports whether m is systemd's inaccessible node: a bind
// from /run/systemd/inaccessible/ on the host's /run tmpfs.
func inaccessible(m protocol.Mount, hostRun protocol.Mount) bool {
	return m.FSType == "tmpfs" && hostRun.Dev != "" && m.Dev == hostRun.Dev &&
		strings.HasPrefix(m.Root, "/systemd/inaccessible/")
}

func under(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// touchesWatched reports whether a mount at p can change what a watched path
// shows: p is a watched path, inside one, or a directory above one ("/"
// excepted).
func touchesWatched(p string) bool {
	if p == "/" {
		return false
	}
	for _, w := range WatchedPaths {
		if under(p, w) || under(w, p) {
			return true
		}
	}
	return false
}

// snapshotDir reports whether an overlay directory is one of containerd's.
// containerd passes relative lower directories ("12/fs") when the option
// would not fit in a page; those are taken as relative to the snapshotter.
func snapshotDir(d string) bool {
	if !path.IsAbs(d) {
		parts := strings.Split(d, "/")
		return len(parts) == 2 && parts[1] == "fs" && strings.Trim(parts[0], "0123456789") == "" && parts[0] != ""
	}
	return under(path.Clean(d), SnapshotterRoot) && !strings.Contains(d, "/../")
}

// CheckMounts applies the mount rules to an audit:
//
//   - every overlay mount, in any namespace, must have its upper, work and
//     lower directories in containerd's snapshotter tree
//   - in every namespace that is not a container's, a mount that touches a
//     watched path must show the host's own files there: the same device
//     and the same subtree as the host's base mount (/, /boot or
//     /boot/efi in PID 1's namespace) that contains it. systemd's
//     read-only views (ProtectSystem) pass this; a tmpfs or another
//     directory bound over /usr/bin does not.
//   - the audit must include PID 1's namespace and must not be truncated
func CheckMounts(a *protocol.MountAudit) []Finding {
	var out []Finding
	if a == nil {
		return []Finding{{Type: CriticalAudit, Detail: "the agent sent no mount audit"}}
	}
	if a.Truncated {
		out = append(out, Finding{Type: CriticalAudit, Detail: "the mount audit was truncated"})
	}
	var host *protocol.MountNamespace
	for i := range a.Namespaces {
		if a.Namespaces[i].PID == 1 {
			host = &a.Namespaces[i]
		}
	}
	if host == nil {
		return append(out, Finding{Type: CriticalAudit, Detail: "the mount audit does not include PID 1's namespace"})
	}
	// The host's base mounts: the first mount at each base path.
	base := map[string]protocol.Mount{}
	for _, m := range host.Mounts {
		if baseMounts[m.MountPoint] {
			if _, ok := base[m.MountPoint]; !ok {
				base[m.MountPoint] = m
			}
		}
	}
	var hostRun protocol.Mount
	for _, m := range host.Mounts {
		if m.MountPoint == "/run" && m.FSType == "tmpfs" && hostRun.Dev == "" {
			hostRun = m
		}
	}
	if _, ok := base["/"]; !ok {
		return append(out, Finding{Type: CriticalAudit, Detail: "PID 1's namespace has no root mount"})
	}
	seen := map[string]bool{}
	add := func(f Finding) {
		k := f.Type + f.Path + f.Detail
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	for _, ns := range a.Namespaces {
		where := fmt.Sprintf("namespace %d (pid %d %s)", ns.ID, ns.PID, ns.Comm)
		for i, m := range ns.Mounts {
			if m.FSType == "overlay" {
				for _, d := range append([]string{m.Upper, m.Work}, m.Lower...) {
					if d != "" && !snapshotDir(d) {
						add(Finding{Type: CriticalOverlay, Path: m.MountPoint,
							Detail: fmt.Sprintf("overlay in %s uses %s, outside %s", where, d, SnapshotterRoot)})
						break
					}
				}
				if m.Upper == "" && len(m.Lower) == 0 {
					add(Finding{Type: CriticalOverlay, Path: m.MountPoint, Detail: "overlay in " + where + " without its directories"})
				}
			}
			if ns.Container || !touchesWatched(m.MountPoint) {
				continue
			}
			if ns.PID == 1 && baseMounts[m.MountPoint] && base[m.MountPoint].Dev == m.Dev && isFirst(ns.Mounts, i, m.MountPoint) {
				continue // the base mount itself
			}
			if inaccessible(m, hostRun) && underAny(m.MountPoint, hiddenOK) {
				continue
			}
			b := containing(base, m.MountPoint)
			want := path.Join(b.Root, strings.TrimPrefix(m.MountPoint, b.MountPoint))
			if m.Dev != b.Dev || path.Clean(m.Root) != path.Clean(want) {
				add(Finding{Type: CriticalBind, Path: m.MountPoint,
					Detail: fmt.Sprintf("%s mount in %s shows %s:%s, not the host's %s:%s", m.FSType, where, m.Dev, m.Root, b.Dev, want)})
			}
		}
	}
	return out
}

func underAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if under(p, d) {
			return true
		}
	}
	return false
}

// isFirst reports whether mounts[i] is the first mount at p.
func isFirst(ms []protocol.Mount, i int, p string) bool {
	for j := 0; j < i; j++ {
		if ms[j].MountPoint == p {
			return false
		}
	}
	return true
}

// containing returns the base mount with the longest mount point that
// contains p.
func containing(base map[string]protocol.Mount, p string) protocol.Mount {
	best := base["/"]
	for mp, m := range base {
		if under(p, mp) && len(mp) > len(best.MountPoint) {
			best = m
		}
	}
	return best
}
