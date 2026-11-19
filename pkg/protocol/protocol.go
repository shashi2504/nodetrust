// Package protocol holds the messages between the agent and the verifier
// (blueprint Phase 3). In step 3.2 they travel as JSON files over SSM; in
// Phase 4 the same messages go over the agent's mTLS endpoint. []byte fields
// are base64 in JSON.
package protocol

import "crypto/sha256"

// Version is the message format version.
const Version = "nodetrust.dev/agent/v2"

// EnrollRequest is what the agent presents: its EK and AK public areas.
type EnrollRequest struct {
	Version    string `json:"version"`
	InstanceID string `json:"instance_id"` // as the node believes it to be; the verifier uses its own
	EKPublic   []byte `json:"ek_public"`   // TPMT_PUBLIC
	AKPublic   []byte `json:"ak_public"`   // TPMT_PUBLIC
}

// Challenge is the verifier's credential, made for the EK the cloud reports
// and the AK the agent presented.
type Challenge struct {
	Version         string `json:"version"`
	IDObject        []byte `json:"id_object"`
	EncryptedSecret []byte `json:"encrypted_secret"`
}

// ChallengeResponse carries the secret the TPM released.
type ChallengeResponse struct {
	Version string `json:"version"`
	Secret  []byte `json:"secret"`
}

// QuoteRequest is one challenge (blueprint 6.2). Before quoting, the agent
// writes the canary to CanaryPath and reads it back, opens every file in the
// sweep set, and lists the mounts of every mount namespace, so the
// measurements they cause land in PCR 10 before the quote.
type QuoteRequest struct {
	Version   string   `json:"version"`
	Nonce     []byte   `json:"nonce"`
	IMAOffset int64    `json:"ima_offset"`       // send the IMA log from this byte offset
	EventLog  bool     `json:"event_log"`        // include the boot event log
	Canary    []byte   `json:"canary,omitempty"` // CanarySize random bytes, or none
	Sweep     []string `json:"sweep,omitempty"`  // absolute paths; directories are walked
	SweepMS   int      `json:"sweep_ms"`         // time budget for the sweep
	Mounts    bool     `json:"mounts"`           // include the mount audit
}

// QuoteResponse is a quote, the PCR values it covers, the IMA log from the
// requested offset read after the quote (so it contains every entry the
// quoted PCR 10 covers), and, when asked, the boot event log (PCRs 0-9;
// fixed after boot), the sweep report and the mount audit. If the log is
// shorter than the requested offset (the node rebooted), the agent sends it
// from the start and says so in IMAOffset.
type QuoteResponse struct {
	Version      string            `json:"version"`
	AgentVersion string            `json:"agent_version"`
	Attest       []byte            `json:"attest"`              // TPMS_ATTEST
	Signature    []byte            `json:"signature"`           // TPMT_SIGNATURE
	PCRs         map[string][]byte `json:"pcrs"`                // "0".."10" -> SHA-256 value
	IMAOffset    int64             `json:"ima_offset"`          // where IMALog starts in the binary log
	IMALog       []byte            `json:"ima_log"`             // binary_runtime_measurements from IMAOffset
	EventLog     []byte            `json:"event_log,omitempty"` // binary_bios_measurements
	Canary       string            `json:"canary,omitempty"`    // "ok", or what went wrong
	Sweep        *SweepReport      `json:"sweep,omitempty"`
	Mounts       *MountAudit       `json:"mounts,omitempty"`
}

// CanaryPath is the file the agent writes the canary to (blueprint 10.3).
// It is on the root file system (ext4), where IMA measures root's reads.
const CanaryPath = "/var/lib/nodetrust/canary"

// CanarySize is the size of a canary value.
const CanarySize = 32

// SweepReport says what the forced-read sweep did (blueprint 10.2). Opening
// a file is enough: IMA measures at open, and only hashes a file that
// changed since its last measurement.
type SweepReport struct {
	Opened  int      `json:"opened"`
	Errors  int      `json:"errors"`
	Samples []string `json:"samples,omitempty"` // the first few errors
	Partial bool     `json:"partial"`           // the time budget ran out
	Millis  int64    `json:"millis"`
}

// MountAudit lists mounts per mount namespace (blueprint 10.3). It is not
// signed by the TPM: it is as trustworthy as the agent, whose binary is in
// the critical set. For a container namespace (its root is an overlay) only
// the overlay mounts are listed.
type MountAudit struct {
	Namespaces []MountNamespace `json:"namespaces"`
	Truncated  bool             `json:"truncated"`
	Errors     int              `json:"errors"` // processes that could not be read
}

// MountNamespace is one mount namespace, seen through one of its processes.
type MountNamespace struct {
	ID        uint64  `json:"id"` // inode of /proc/<pid>/ns/mnt
	PID       int     `json:"pid"`
	Comm      string  `json:"comm"`
	Container bool    `json:"container"` // its root mount is an overlay
	Mounts    []Mount `json:"mounts"`
}

// Mount is one line of /proc/<pid>/mountinfo, unescaped.
type Mount struct {
	MountPoint string   `json:"mount_point"`
	Root       string   `json:"root"` // the subtree of the file system mounted here
	Dev        string   `json:"dev"`  // major:minor
	FSType     string   `json:"fstype"`
	Source     string   `json:"source"`
	Lower      []string `json:"lower,omitempty"` // overlay only
	Upper      string   `json:"upper,omitempty"`
	Work       string   `json:"work,omitempty"`
}

// HintRequest waits until the node's IMA log has more than Count entries,
// or about 25 seconds. The verifier uses the answer to challenge at once
// (blueprint 10.5); a hint is only advisory.
type HintRequest struct {
	Version string `json:"version"`
	Count   uint64 `json:"count"`
}

// HintResponse is the current number of IMA measurements.
type HintResponse struct {
	Version string `json:"version"`
	Count   uint64 `json:"count"`
}

// NonceSize is the size of every verifier nonce.
const NonceSize = 32

// BindNonce is the value the TPM signs as qualifying data in a quote over
// the network: the verifier's nonce bound to the agent's TLS key for this
// connection. The agent computes it from its own certificate, the verifier
// from the certificate it saw in the handshake. A man in the middle that
// terminates TLS with another key makes the two values differ, so the quote
// fails even if the relayed bytes are untouched.
func BindNonce(nonce, agentSPKI []byte) []byte {
	k := sha256.Sum256(agentSPKI)
	h := sha256.New()
	h.Write([]byte("nodetrust-quote-binding/v1\x00"))
	h.Write(nonce)
	h.Write(k[:])
	return h.Sum(nil)
}
