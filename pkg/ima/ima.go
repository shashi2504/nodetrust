// Package ima parses the Linux IMA binary measurement log and replays it
// against a quoted PCR 10 (the Go version of infra/phase1/ima_replay.py,
// checked against it in the tests).
//
// For each entry the kernel extends PCR 10 of every bank with
// H_bank(template data); a violation (all-zero SHA-1 template digest) is
// extended as all 0xFF bytes. The kernel appends to the log before it
// extends the PCR, so a log read after the quote holds every entry the quote
// covers plus possibly some newer ones: the verifier accepts the log when a
// prefix of it replays to the quoted value.
package ima

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// PCR is the PCR IMA extends.
const PCR = 10

// Entry is one record of the binary log.
type Entry struct {
	PCR            uint32
	TemplateDigest [20]byte // SHA-1 of the template data; zero for a violation
	TemplateName   string
	TemplateData   []byte
	Size           int // bytes the entry takes in the binary log
}

// Violation reports whether the entry records a measurement violation.
func (e *Entry) Violation() bool { return e.TemplateDigest == [20]byte{} }

// ParseLog parses binary_runtime_measurements (little endian, x86 and arm64).
func ParseLog(b []byte) ([]Entry, error) {
	var out []Entry
	off := 0
	need := func(n int) error {
		if off+n > len(b) || n < 0 {
			return fmt.Errorf("ima log: entry %d truncated at offset %d", len(out), off)
		}
		return nil
	}
	for off < len(b) {
		start := off
		var e Entry
		if err := need(4 + 20 + 4); err != nil {
			return nil, err
		}
		e.PCR = binary.LittleEndian.Uint32(b[off:])
		copy(e.TemplateDigest[:], b[off+4:off+24])
		nameLen := int(binary.LittleEndian.Uint32(b[off+24:]))
		off += 28
		if nameLen > 255 {
			return nil, fmt.Errorf("ima log: entry %d has a %d-byte template name", len(out), nameLen)
		}
		if err := need(nameLen + 4); err != nil {
			return nil, err
		}
		e.TemplateName = string(b[off : off+nameLen])
		off += nameLen
		dataLen := int(binary.LittleEndian.Uint32(b[off:]))
		off += 4
		if err := need(dataLen); err != nil {
			return nil, err
		}
		e.TemplateData = b[off : off+dataLen]
		off += dataLen
		if e.TemplateName == "ima" {
			return nil, fmt.Errorf("ima log: entry %d uses the legacy 'ima' template; boot with ima_template=ima-ng", len(out))
		}
		e.Size = off - start
		out = append(out, e)
	}
	return out, nil
}

// ReplayResult describes the log prefix that matched the quoted PCR.
type ReplayResult struct {
	Attested      int    // PCR 10 entries in the matching prefix
	After         int    // entries after it (appended after the quote)
	SHA1Mismatch  int    // entries in the prefix whose SHA-1 template digest is wrong
	MatchedPrefix int    // number of log entries (any PCR) in the prefix
	Bytes         int64  // size of the matching prefix in the binary log
	Final         []byte // PCR 10 after the prefix (equals the quoted value)
}

// Replay finds the shortest prefix of the log whose SHA-256 replay of PCR 10
// equals quoted. An empty log matches an all-zero PCR. It fails if no prefix
// matches, or if any entry in the matching prefix has a SHA-1 template
// digest that does not match its data (a log edited without the PCR).
func Replay(entries []Entry, quoted []byte) (*ReplayResult, error) {
	return ReplayFrom(entries, make([]byte, sha256.Size), quoted)
}

// ReplayFrom is Replay for the part of a log that follows an already
// verified prefix whose replay ended at start (an incremental log, blueprint
// 6.2). No new entries match when start already equals quoted.
func ReplayFrom(entries []Entry, start, quoted []byte) (*ReplayResult, error) {
	if len(quoted) != sha256.Size || len(start) != sha256.Size {
		return nil, errors.New("ima replay: PCR 10 values must be SHA-256")
	}
	pcr := append([]byte(nil), start...)
	if bytes.Equal(pcr, quoted) {
		return &ReplayResult{After: len(entries), Final: pcr}, nil
	}
	ff := bytes.Repeat([]byte{0xff}, sha256.Size)
	used, bad := 0, 0
	var size int64
	for i := range entries {
		e := &entries[i]
		size += int64(e.Size)
		if e.PCR != PCR {
			continue
		}
		used++
		var m []byte
		if e.Violation() {
			m = ff
		} else {
			if sha1.Sum(e.TemplateData) != e.TemplateDigest {
				bad++
			}
			h := sha256.Sum256(e.TemplateData)
			m = h[:]
		}
		next := sha256.Sum256(append(pcr, m...))
		pcr = next[:]
		if bytes.Equal(pcr, quoted) {
			if bad != 0 {
				return nil, fmt.Errorf("ima replay: %d entries in the attested prefix have a wrong SHA-1 template digest", bad)
			}
			return &ReplayResult{Attested: used, After: len(entries) - i - 1, MatchedPrefix: i + 1, Bytes: size, Final: pcr}, nil
		}
	}
	return nil, errors.New("ima replay: no prefix of the log replays to the quoted PCR 10")
}

// Measurement is the file path and digest of an ima-ng entry.
type Measurement struct {
	Algo   string // "sha256"
	Digest []byte
	Path   []byte
}

// DecodeNG decodes ima-ng template data: d-ng (algo ":" NUL digest) and n-ng
// (NUL-terminated path), each with a 4-byte little-endian length.
func DecodeNG(data []byte) (*Measurement, error) {
	var fields [][]byte
	for off := 0; off < len(data); {
		if off+4 > len(data) {
			return nil, errors.New("ima-ng: truncated field length")
		}
		n := int(binary.LittleEndian.Uint32(data[off:]))
		off += 4
		if n < 0 || off+n > len(data) {
			return nil, errors.New("ima-ng: truncated field")
		}
		fields = append(fields, data[off:off+n])
		off += n
	}
	if len(fields) != 2 {
		return nil, fmt.Errorf("ima-ng: %d fields, want 2", len(fields))
	}
	d, name := fields[0], fields[1]
	sep := bytes.IndexByte(d, 0)
	if sep < 1 || d[sep-1] != ':' {
		return nil, errors.New("ima-ng: digest field has no 'algo:' prefix")
	}
	return &Measurement{Algo: string(d[:sep-1]), Digest: d[sep+1:], Path: bytes.TrimSuffix(name, []byte{0})}, nil
}
