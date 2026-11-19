// Package eventlog parses the TCG PC Client crypto-agile boot event log
// (/sys/kernel/security/tpm0/binary_bios_measurements) and replays it to
// PCRs (blueprint Phase 4, step 4.1). Standard library only.
//
// Format (TCG PC Client Platform Firmware Profile, section 10): the first
// event is a legacy TCG_PCR_EVENT (SHA-1 layout) holding the "Spec ID
// Event03" header that lists the digest algorithms; every following event is
// a TCG_PCR_EVENT2 with one digest per algorithm. All integers are little
// endian.
package eventlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Event types used by NitroTPM firmware, shim, GRUB and the kernel.
const (
	EvPrebootCert             = 0x00000000
	EvPostCode                = 0x00000001
	EvNoAction                = 0x00000003
	EvSeparator               = 0x00000004
	EvAction                  = 0x00000005
	EvEventTag                = 0x00000006
	EvSCRTMContents           = 0x00000007
	EvSCRTMVersion            = 0x00000008
	EvIPL                     = 0x0000000D
	EvEFIVariableDriverConfig = 0x80000001
	EvEFIVariableBoot         = 0x80000002
	EvEFIBootServicesApp      = 0x80000003
	EvEFIAction               = 0x80000007
	EvEFIPlatformFirmwareBlob = 0x80000008
	EvEFIGPTEvent             = 0x80000006
	EvEFIVariableAuthority    = 0x800000E0
)

var typeNames = map[uint32]string{
	EvPrebootCert: "EV_PREBOOT_CERT", EvPostCode: "EV_POST_CODE", EvNoAction: "EV_NO_ACTION",
	EvSeparator: "EV_SEPARATOR", EvAction: "EV_ACTION", EvEventTag: "EV_EVENT_TAG",
	EvSCRTMContents: "EV_S_CRTM_CONTENTS", EvSCRTMVersion: "EV_S_CRTM_VERSION", EvIPL: "EV_IPL",
	EvEFIVariableDriverConfig: "EV_EFI_VARIABLE_DRIVER_CONFIG", EvEFIVariableBoot: "EV_EFI_VARIABLE_BOOT",
	EvEFIBootServicesApp: "EV_EFI_BOOT_SERVICES_APPLICATION", EvEFIAction: "EV_EFI_ACTION",
	EvEFIPlatformFirmwareBlob: "EV_EFI_PLATFORM_FIRMWARE_BLOB", EvEFIGPTEvent: "EV_EFI_GPT_EVENT",
	EvEFIVariableAuthority: "EV_EFI_VARIABLE_AUTHORITY",
}

// TypeName returns the TCG name of an event type.
func TypeName(t uint32) string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("0x%08x", t)
}

const algSHA256 = 0x000B

// Event is one TCG_PCR_EVENT2 with its SHA-256 digest.
type Event struct {
	Index  int // position in the log, the header being 0
	PCR    uint32
	Type   uint32
	SHA256 []byte
	Data   []byte
}

// Log is a parsed event log.
type Log struct {
	Algorithms map[uint16]int // algorithm ID -> digest size, from the Spec ID event
	Events     []Event        // TCG_PCR_EVENT2 records, header excluded
}

type rd struct {
	b   []byte
	off int
	err error
}

func (r *rd) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.off+n > len(r.b) {
		r.err = fmt.Errorf("truncated at offset %d", r.off)
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

func (r *rd) u8() uint8 {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *rd) u16() uint16 {
	if b := r.take(2); b != nil {
		return binary.LittleEndian.Uint16(b)
	}
	return 0
}

func (r *rd) u64() uint64 {
	if b := r.take(8); b != nil {
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

func (r *rd) u32() uint32 {
	if b := r.take(4); b != nil {
		return binary.LittleEndian.Uint32(b)
	}
	return 0
}

// maxEventSize bounds a single event (the largest real ones, db and dbx, are
// tens of KB).
const maxEventSize = 1 << 20

// Parse parses a crypto-agile event log. It requires a SHA-256 bank.
func Parse(b []byte) (*Log, error) {
	r := &rd{b: b}
	// Header: TCG_PCR_EVENT with a SHA-1 sized digest field.
	r.u32() // PCR index (0)
	if t := r.u32(); t != EvNoAction && r.err == nil {
		return nil, fmt.Errorf("event log: first event is %s, not the Spec ID event", TypeName(t))
	}
	r.take(20)
	hdr := r.take(int(r.u32()))
	if r.err != nil {
		return nil, fmt.Errorf("event log header: %w", r.err)
	}
	h := &rd{b: hdr}
	if sig := h.take(16); !bytes.Equal(sig, []byte("Spec ID Event03\x00")) {
		return nil, errors.New("event log: not a crypto-agile log (no \"Spec ID Event03\" header)")
	}
	h.u32() // platformClass
	h.u8()  // specVersionMinor
	h.u8()  // specVersionMajor
	h.u8()  // specErrata
	h.u8()  // uintnSize
	n := h.u32()
	if n == 0 || n > 8 {
		return nil, fmt.Errorf("event log: %d digest algorithms", n)
	}
	l := &Log{Algorithms: map[uint16]int{}}
	for i := uint32(0); i < n; i++ {
		id, size := h.u16(), h.u16()
		l.Algorithms[id] = int(size)
	}
	if h.err != nil {
		return nil, fmt.Errorf("event log header: %w", h.err)
	}
	if l.Algorithms[algSHA256] != sha256.Size {
		return nil, errors.New("event log: no SHA-256 bank")
	}

	for r.off < len(b) {
		e := Event{Index: len(l.Events) + 1}
		e.PCR = r.u32()
		e.Type = r.u32()
		count := r.u32()
		if r.err == nil && count != n {
			return nil, fmt.Errorf("event log: event %d has %d digests, header says %d", e.Index, count, n)
		}
		for i := uint32(0); i < count && r.err == nil; i++ {
			id := r.u16()
			size, ok := l.Algorithms[id]
			if !ok {
				return nil, fmt.Errorf("event log: event %d uses algorithm 0x%04x not in the header", e.Index, id)
			}
			d := r.take(size)
			if id == algSHA256 {
				e.SHA256 = d
			}
		}
		size := r.u32()
		if size > maxEventSize {
			return nil, fmt.Errorf("event log: event %d is %d bytes", e.Index, size)
		}
		e.Data = r.take(int(size))
		if r.err != nil {
			return nil, fmt.Errorf("event log: event %d: %w", e.Index, r.err)
		}
		if e.PCR > 23 {
			return nil, fmt.Errorf("event log: event %d extends PCR %d", e.Index, e.PCR)
		}
		l.Events = append(l.Events, e)
	}
	return l, nil
}

// Replay computes the SHA-256 PCR values the log produces. EV_NO_ACTION
// events are not extended. PCR 0 starts at the startup locality when the log
// records one (a "StartupLocality" EV_NO_ACTION event), else at zero.
func (l *Log) Replay() map[uint32][]byte {
	pcrs := map[uint32][]byte{}
	for _, e := range l.Events {
		if e.Type == EvNoAction {
			if e.PCR == 0 && bytes.HasPrefix(e.Data, []byte("StartupLocality\x00")) && len(e.Data) >= 17 {
				v := make([]byte, sha256.Size)
				v[sha256.Size-1] = e.Data[16]
				pcrs[0] = v
			}
			continue
		}
		cur, ok := pcrs[e.PCR]
		if !ok {
			cur = make([]byte, sha256.Size)
		}
		next := sha256.Sum256(append(append([]byte{}, cur...), e.SHA256...))
		pcrs[e.PCR] = next[:]
	}
	return pcrs
}

// CheckReplay replays the log and compares PCRs 0-9 with quoted values
// (from a verified quote). A log that does not replay to the quote cannot
// be trusted for any of the event checks.
func (l *Log) CheckReplay(quoted map[int][]byte) error {
	got := l.Replay()
	for i := 0; i <= 9; i++ {
		q, ok := quoted[i]
		if !ok {
			return fmt.Errorf("event log: PCR %d was not quoted", i)
		}
		v, ok := got[uint32(i)]
		if !ok {
			v = make([]byte, sha256.Size)
		}
		if !bytes.Equal(v, q) {
			return fmt.Errorf("event log: replay of PCR %d is %x, quote says %x", i, v, q)
		}
	}
	return nil
}

// --- event data helpers ---------------------------------------------------------

// String returns EV_IPL and EV_EFI_ACTION data as text, without a trailing NUL.
func (e *Event) String() string {
	return string(bytes.TrimRight(e.Data, "\x00"))
}

// Variable is the UEFI_VARIABLE_DATA of an EV_EFI_VARIABLE_* event.
type Variable struct {
	GUID [16]byte
	Name string
	Data []byte
}

// ParseVariable decodes UEFI_VARIABLE_DATA: GUID, name length (UINT64, in
// UTF-16 characters), data length (UINT64), name (UTF-16LE), data.
func (e *Event) ParseVariable() (*Variable, error) {
	r := &rd{b: e.Data}
	v := &Variable{}
	copy(v.GUID[:], r.take(16))
	nameLen := r.u64()
	dataLen := r.u64()
	if nameLen > 1024 || dataLen > maxEventSize {
		return nil, errors.New("variable event: bad lengths")
	}
	name := r.take(int(nameLen) * 2)
	v.Data = r.take(int(dataLen))
	if r.err != nil {
		return nil, fmt.Errorf("variable event %d: %w", e.Index, r.err)
	}
	u := make([]uint16, nameLen)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(name[2*i:])
	}
	v.Name = string(utf16.Decode(u))
	return v, nil
}

// LoadOptionDescription returns the description of an EFI_LOAD_OPTION
// (Boot#### variable data): UINT32 attributes, UINT16 file path list length,
// then the NUL-terminated UTF-16 description.
func LoadOptionDescription(data []byte) (string, error) {
	if len(data) < 6 {
		return "", errors.New("load option: too short")
	}
	var u []uint16
	for i := 6; i+1 < len(data); i += 2 {
		c := binary.LittleEndian.Uint16(data[i:])
		if c == 0 {
			return string(utf16.Decode(u)), nil
		}
		u = append(u, c)
	}
	return "", errors.New("load option: description not terminated")
}
