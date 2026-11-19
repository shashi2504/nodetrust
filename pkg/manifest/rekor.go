package manifest

// Rekor transparency log check (blueprint Phase 2, step 2.3).
//
// The signed statement's hash and signature are recorded in the public
// Rekor v1 log as a hashedrekord entry. The verifier checks the saved entry
// offline, with only the pinned Rekor public key:
//
//  1. the entry is for this statement, this signature and the pinned signing key
//  2. Rekor's signed entry timestamp (SET) over the entry is valid
//  3. the RFC 6962 inclusion proof leads from the entry to the tree root
//  4. Rekor's signed checkpoint commits to that root and tree size
//
// Passing means the signature was publicly logged at integratedTime. A
// signature made with a stolen key but never logged, or logged later, is
// visible as such.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

// RekorEntry is one entry as Rekor v1 returns it from POST or GET
// /api/v1/log/entries (the value under the entry UUID).
type RekorEntry struct {
	Body           string `json:"body"`
	IntegratedTime int64  `json:"integratedTime"`
	LogID          string `json:"logID"`
	LogIndex       int64  `json:"logIndex"`
	Verification   struct {
		InclusionProof struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   int64    `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   int64    `json:"treeSize"`
		} `json:"inclusionProof"`
		SignedEntryTimestamp string `json:"signedEntryTimestamp"`
	} `json:"verification"`
}

// RekorResult is what a verified entry proves.
type RekorResult struct {
	UUID           string
	LogIndex       int64
	IntegratedTime time.Time
	TreeSize       int64
	RootHash       string
}

// ParseRekorResponse reads a saved Rekor response: a JSON object with one
// key, the entry UUID.
func ParseRekorResponse(b []byte) (string, *RekorEntry, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return "", nil, fmt.Errorf("rekor entry: %w", err)
	}
	if len(m) != 1 {
		return "", nil, fmt.Errorf("rekor entry: want exactly one entry, got %d", len(m))
	}
	for uuid, raw := range m {
		var e RekorEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			return "", nil, fmt.Errorf("rekor entry: %w", err)
		}
		return uuid, &e, nil
	}
	panic("unreachable")
}

// hashedrekord is the body Rekor stores for our entry type.
type hashedrekord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// VerifyRekor checks a Rekor entry against the statement bytes, its
// signature (base64 DER, as in statement.sig), the pinned signing key and
// the pinned Rekor key.
func VerifyRekor(uuid string, e *RekorEntry, statement, sigB64 []byte, signer, rekor *ecdsa.PublicKey) (*RekorResult, error) {
	rekorDER, err := x509.MarshalPKIXPublicKey(rekor)
	if err != nil {
		return nil, fmt.Errorf("rekor: %w", err)
	}
	logID := sha256.Sum256(rekorDER)
	if e.LogID != hex.EncodeToString(logID[:]) {
		return nil, fmt.Errorf("rekor: entry is from log %s, not the pinned log %x", e.LogID, logID)
	}

	// 1. The entry is ours.
	body, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return nil, fmt.Errorf("rekor: body is not base64: %w", err)
	}
	var hr hashedrekord
	if err := json.Unmarshal(body, &hr); err != nil {
		return nil, fmt.Errorf("rekor: body: %w", err)
	}
	if hr.Kind != "hashedrekord" || hr.Spec.Data.Hash.Algorithm != "sha256" {
		return nil, fmt.Errorf("rekor: entry kind %q/%q, want hashedrekord/sha256", hr.Kind, hr.Spec.Data.Hash.Algorithm)
	}
	if want := sum(statement); hr.Spec.Data.Hash.Value != want {
		return nil, fmt.Errorf("rekor: entry is for hash %s, statement hash is %s", hr.Spec.Data.Hash.Value, want)
	}
	gotSig, err := base64.StdEncoding.DecodeString(hr.Spec.Signature.Content)
	if err != nil {
		return nil, errors.New("rekor: entry signature is not base64")
	}
	ourSig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sigB64)))
	if err != nil || !bytes.Equal(gotSig, ourSig) {
		return nil, errors.New("rekor: entry holds a different signature")
	}
	pemBytes, err := base64.StdEncoding.DecodeString(hr.Spec.Signature.PublicKey.Content)
	if err != nil {
		return nil, errors.New("rekor: entry public key is not base64")
	}
	entryKey, err := ParsePublicKeyPEM(pemBytes)
	if err != nil || !entryKey.Equal(signer) {
		return nil, errors.New("rekor: entry was made with a different signing key")
	}

	// 2. Signed entry timestamp: Rekor's signature over the canonical JSON
	// of body, integratedTime, logID and logIndex (keys in sorted order).
	set, err := base64.StdEncoding.DecodeString(e.Verification.SignedEntryTimestamp)
	if err != nil {
		return nil, errors.New("rekor: signedEntryTimestamp is not base64")
	}
	payload, err := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{e.Body, e.IntegratedTime, e.LogID, e.LogIndex})
	if err != nil {
		return nil, err
	}
	d := sha256.Sum256(payload)
	if !ecdsa.VerifyASN1(rekor, d[:], set) {
		return nil, errors.New("rekor: signed entry timestamp does not verify")
	}

	// 3. Inclusion proof.
	p := e.Verification.InclusionProof
	if p.TreeSize <= 0 || p.LogIndex < 0 || p.LogIndex >= p.TreeSize {
		return nil, fmt.Errorf("rekor: bad inclusion proof index %d / size %d", p.LogIndex, p.TreeSize)
	}
	root, err := hex.DecodeString(p.RootHash)
	if err != nil || len(root) != sha256.Size {
		return nil, errors.New("rekor: bad root hash")
	}
	proof := make([][]byte, len(p.Hashes))
	for i, h := range p.Hashes {
		if proof[i], err = hex.DecodeString(h); err != nil || len(proof[i]) != sha256.Size {
			return nil, errors.New("rekor: bad proof hash")
		}
	}
	leaf := sha256.Sum256(append([]byte{0}, body...))
	if err := verifyInclusion(uint64(p.LogIndex), uint64(p.TreeSize), leaf[:], proof, root); err != nil {
		return nil, fmt.Errorf("rekor: %w", err)
	}

	// 4. Checkpoint signed by the log commits to the same root and size.
	if err := verifyCheckpoint(p.Checkpoint, rekor, rekorDER, p.TreeSize, root); err != nil {
		return nil, fmt.Errorf("rekor: %w", err)
	}

	return &RekorResult{
		UUID:           uuid,
		LogIndex:       e.LogIndex,
		IntegratedTime: time.Unix(e.IntegratedTime, 0).UTC(),
		TreeSize:       p.TreeSize,
		RootHash:       p.RootHash,
	}, nil
}

// --- RFC 6962 Merkle inclusion ------------------------------------------------

func hashChildren(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// verifyInclusion checks an RFC 6962 / RFC 9162 inclusion proof.
func verifyInclusion(index, size uint64, leaf []byte, proof [][]byte, root []byte) error {
	if index >= size {
		return fmt.Errorf("inclusion proof: index %d not below size %d", index, size)
	}
	inner := bits.Len64(index ^ (size - 1))
	border := bits.OnesCount64(index >> uint(inner))
	if len(proof) != inner+border {
		return fmt.Errorf("inclusion proof: %d hashes, want %d", len(proof), inner+border)
	}
	h := leaf
	for i, p := range proof[:inner] {
		if (index>>uint(i))&1 == 0 {
			h = hashChildren(h, p)
		} else {
			h = hashChildren(p, h)
		}
	}
	for _, p := range proof[inner:] {
		h = hashChildren(p, h)
	}
	if !bytes.Equal(h, root) {
		return errors.New("inclusion proof does not lead to the root hash")
	}
	return nil
}

// --- signed checkpoint (signed note format) -----------------------------------

// verifyCheckpoint checks a Rekor checkpoint:
//
//	<origin>\n<tree size>\n<base64 root hash>\n[other lines\n]\n
//	— <signer name> <base64(4-byte key hint || DER ECDSA signature)>\n
//
// The signature is over the text before the blank line, newline included.
// The key hint is the first 4 bytes of SHA-256 of the log's PKIX public key.
func verifyCheckpoint(cp string, rekor *ecdsa.PublicKey, rekorDER []byte, size int64, root []byte) error {
	text, sigs, ok := strings.Cut(cp, "\n\n")
	if !ok {
		return errors.New("checkpoint: no signature block")
	}
	text += "\n"
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return errors.New("checkpoint: too few lines")
	}
	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n != size {
		return fmt.Errorf("checkpoint: tree size %q, proof says %d", lines[1], size)
	}
	r, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || !bytes.Equal(r, root) {
		return errors.New("checkpoint: root hash differs from the inclusion proof")
	}

	hint := sha256.Sum256(rekorDER)
	d := sha256.Sum256([]byte(text))
	for _, line := range strings.Split(strings.TrimSpace(sigs), "\n") {
		rest, ok := strings.CutPrefix(line, "— ")
		if !ok {
			continue
		}
		i := strings.LastIndexByte(rest, ' ')
		if i < 0 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(rest[i+1:])
		if err != nil || len(raw) < 5 || !bytes.Equal(raw[:4], hint[:4]) {
			continue
		}
		if ecdsa.VerifyASN1(rekor, d[:], raw[4:]) {
			return nil
		}
		return errors.New("checkpoint: signature does not verify")
	}
	return errors.New("checkpoint: no signature from the pinned log key")
}
