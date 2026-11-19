package manifest

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Entry is one file system object in a reference manifest.
type Entry struct {
	Path   string `json:"path"`
	Type   string `json:"type"` // file, dir, symlink, other
	SHA256 string `json:"sha256,omitempty"`
	// Authenticode is the PE Authenticode SHA-256 of an EFI image under
	// /boot (shim, GRUB, the kernel): the digest that goes into PCR 4.
	Authenticode string `json:"authenticode_sha256,omitempty"`
}

// Index parses manifest JSON (as returned by CheckManifestGz, so already
// checked against the signed statement) into a map from path to entry.
func Index(raw []byte) (map[string]Entry, error) {
	var m struct {
		Entries []Entry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	idx := make(map[string]Entry, len(m.Entries))
	for _, e := range m.Entries {
		if _, dup := idx[e.Path]; dup {
			return nil, fmt.Errorf("manifest: duplicate path %s", e.Path)
		}
		idx[e.Path] = e
	}
	// IMA writes a file name with whitespace in it with each whitespace
	// character replaced by '_' (seen on a worker, 2026-11-19: setuptools'
	// "script (dev).tmpl" is logged as "script_(dev).tmpl"). The log path is
	// then looked up under that name too. The entry still carries the real
	// path, and the hash must still match, so a file created under the
	// underscored name only passes if it has the reference content. A real
	// file with the underscored name takes precedence.
	for _, e := range m.Entries {
		alias := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\n' {
				return '_'
			}
			return r
		}, e.Path)
		if _, taken := idx[alias]; !taken {
			idx[alias] = e
		}
	}
	return idx, nil
}
