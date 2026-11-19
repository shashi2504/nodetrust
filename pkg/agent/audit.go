package agent

// What the agent does before each quote (blueprint 6.2 step 2): the IMA
// canary, the forced-read sweep and the mount audit. The agent only
// collects; the verifier decides what the results mean.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"nodetrust/pkg/protocol"
)

// WriteCanary writes value to path and reads it back as a separate open, so
// IMA measures the new content (root read on ext4). It returns "ok" or what
// went wrong; the verifier expects an IMA entry for path with
// sha256(value) in the quoted log either way.
func WriteCanary(path string, value []byte) string {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err.Error()
	}
	if err := os.WriteFile(path, value, 0o600); err != nil {
		return err.Error()
	}
	got, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	if !bytes.Equal(got, value) {
		return "read back a different value"
	}
	return "ok"
}

// maxSamples bounds the error samples in a sweep report.
const maxSamples = 5

// Sweep opens every regular file under paths (directories are walked;
// symbolic links and special files are skipped, so a FIFO cannot block the
// sweep and a link cannot lead out of the set). Opening is enough for IMA's
// FILE_CHECK hook. It stops when the budget runs out.
func Sweep(paths []string, budget time.Duration) *protocol.SweepReport {
	start := time.Now()
	r := &protocol.SweepReport{}
	note := func(p string, err error) {
		r.Errors++
		if len(r.Samples) < maxSamples {
			r.Samples = append(r.Samples, p+": "+err.Error())
		}
	}
	open := func(p string) {
		f, err := os.Open(p)
		if err != nil {
			note(p, err)
			return
		}
		f.Close()
		r.Opened++
	}
	errBudget := errors.New("budget")
	for _, root := range paths {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			note(root, errors.New("not a clean absolute path"))
			continue
		}
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if time.Since(start) > budget {
				return errBudget
			}
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					note(p, err)
				}
				return nil
			}
			if d.Type().IsRegular() {
				open(p)
			}
			return nil
		})
		if errors.Is(err, errBudget) {
			r.Partial = true
			break
		}
	}
	r.Millis = time.Since(start).Milliseconds()
	return r
}

// maxMounts bounds the size of a mount audit.
const maxMounts = 20000

// AuditMounts lists the mounts of every mount namespace that has a process,
// reading <proc>/<pid>/ns/mnt and <proc>/<pid>/mountinfo (this needs
// CAP_SYS_PTRACE for processes with more capabilities than the agent). A
// mount namespace with no process (held open by a file descriptor or a bind
// mount of its nsfs file) is not seen; the audit is a snapshot.
func AuditMounts(proc string) *protocol.MountAudit {
	a := &protocol.MountAudit{}
	ents, err := os.ReadDir(proc)
	if err != nil {
		a.Errors++
		return a
	}
	pids := make([]int, 0, len(ents))
	for _, e := range ents {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids) // PID 1 first: its namespace is the host's
	seen := map[uint64]bool{}
	total := 0
	for _, pid := range pids {
		dir := filepath.Join(proc, strconv.Itoa(pid))
		link, err := os.Readlink(filepath.Join(dir, "ns", "mnt"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) { // a process that exited is not an error
				a.Errors++
			}
			continue
		}
		id, ok := nsInode(link)
		if !ok || seen[id] {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "mountinfo"))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				a.Errors++
			}
			continue
		}
		ms, err := ParseMountinfo(raw)
		if err != nil {
			a.Errors++
			continue
		}
		seen[id] = true
		comm, _ := os.ReadFile(filepath.Join(dir, "comm"))
		ns := protocol.MountNamespace{ID: id, PID: pid, Comm: strings.TrimSpace(string(comm))}
		ns.Container = len(ms) > 0 && rootMount(ms).FSType == "overlay"
		for _, m := range ms {
			if ns.Container && m.FSType != "overlay" {
				continue
			}
			if total >= maxMounts {
				a.Truncated = true
				break
			}
			ns.Mounts = append(ns.Mounts, m)
			total++
		}
		a.Namespaces = append(a.Namespaces, ns)
	}
	return a
}

// rootMount is the last mount at "/" (the one on top).
func rootMount(ms []protocol.Mount) protocol.Mount {
	var r protocol.Mount
	for _, m := range ms {
		if m.MountPoint == "/" {
			r = m
		}
	}
	return r
}

// nsInode parses "mnt:[4026531841]".
func nsInode(link string) (uint64, bool) {
	if !strings.HasPrefix(link, "mnt:[") || !strings.HasSuffix(link, "]") {
		return 0, false
	}
	id, err := strconv.ParseUint(link[5:len(link)-1], 10, 64)
	return id, err == nil
}

// ParseMountinfo parses /proc/<pid>/mountinfo (proc(5)):
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
func ParseMountinfo(b []byte) ([]protocol.Mount, error) {
	var out []protocol.Mount
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 4<<20) // overlay lines with many layers are long
	for n := 1; sc.Scan(); n++ {
		f := strings.Split(sc.Text(), " ")
		sep := -1
		for i := 6; i < len(f); i++ {
			if f[i] == "-" {
				sep = i
				break
			}
		}
		if len(f) < 6 || sep < 0 || sep+3 > len(f) {
			return nil, fmt.Errorf("mountinfo line %d: malformed", n)
		}
		m := protocol.Mount{
			Dev:        f[2],
			Root:       unescape(f[3]),
			MountPoint: unescape(f[4]),
			FSType:     f[sep+1],
			Source:     unescape(f[sep+2]),
		}
		if m.FSType == "overlay" && sep+3 < len(f) {
			for _, o := range splitOptions(f[sep+3]) {
				k, v, _ := strings.Cut(o, "=")
				switch k {
				case "lowerdir":
					m.Lower = append(m.Lower, splitLower(v)...)
				case "lowerdir+", "datadir+":
					m.Lower = append(m.Lower, v)
				case "upperdir":
					m.Upper = v
				case "workdir":
					m.Work = v
				}
			}
		}
		out = append(out, m)
	}
	return out, sc.Err()
}

// unescape undoes mountinfo's octal escapes (\040 space, \011 tab, \012
// newline, \134 backslash).
func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// splitOptions splits super options on commas, keeping escaped commas
// ("\,") in values.
func splitOptions(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == ',':
			cur.WriteByte(',')
			i++
		case s[i] == ',':
			out = append(out, unescape(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, unescape(cur.String()))
}

// splitLower splits an overlay lowerdir list on ':' (an escaped "\:" is part
// of a name; "::" separates data-only layers).
func splitLower(v string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(v); i++ {
		switch {
		case v[i] == '\\' && i+1 < len(v) && v[i+1] == ':':
			cur.WriteByte(':')
			i++
		case v[i] == ':':
			if cur.Len() > 0 {
				out = append(out, cur.String())
			}
			cur.Reset()
		default:
			cur.WriteByte(v[i])
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// MeasurementCount reads IMA's runtime_measurements_count.
func MeasurementCount(path string) (uint64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
}
