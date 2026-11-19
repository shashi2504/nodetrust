// Package manifest verifies signed reference manifests (blueprint Phase 2).
//
// A reference manifest (built by infra/phase2/manifest.py) lists every file
// of a golden AMI. It is not signed directly. Instead a short statement binds
// the AMI and snapshot IDs to the SHA-256 of the manifest, and the statement
// is signed with the KMS key (ECDSA P-256, SHA-256). The signature covers the
// exact statement bytes, so no JSON canonicalisation is needed to verify it.
//
// Verification order: signature over the statement, then the statement's
// fields, then the manifest bytes against the hashes in the statement.
package manifest

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"regexp"
)

// Schema identifiers.
const (
	StatementSchema = "nodetrust.dev/manifest-statement/v1"
	ManifestSchema  = "nodetrust.dev/manifest/v1"
)

// Limits keep a hostile input from exhausting memory.
const (
	maxStatementBytes   = 64 << 10
	maxManifestJSONSize = 512 << 20
)

// Statement is the signed object.
type Statement struct {
	Schema           string            `json:"schema"`
	AMIID            string            `json:"ami_id"`
	SnapshotID       string            `json:"snapshot_id"`
	Region           string            `json:"region"`
	ManifestURI      string            `json:"manifest_uri"`
	ManifestSHA256   string            `json:"manifest_sha256"`
	ManifestGzSHA256 string            `json:"manifest_gz_sha256"`
	EntriesSHA256    string            `json:"entries_sha256"`
	BuildInfo        map[string]string `json:"build_info"`
	KeyID            string            `json:"key_id"`
	SignedAt         string            `json:"signed_at"`
}

var (
	reAMI    = regexp.MustCompile(`^ami-[0-9a-f]{8,17}$`)
	reSnap   = regexp.MustCompile(`^snap-[0-9a-f]{8,17}$`)
	reSHA256 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ErrBadSignature means the signature does not match the statement and key.
var ErrBadSignature = errors.New("manifest statement: signature does not verify")

// ParsePublicKeyPEM parses a PKIX "PUBLIC KEY" PEM block holding a P-256
// ECDSA key, as exported from KMS by GetPublicKey.
func ParsePublicKeyPEM(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("public key: no PUBLIC KEY PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, errors.New("public key: not an ECDSA P-256 key")
	}
	return ek, nil
}

// VerifyStatement checks sigB64 (base64 of an ASN.1 DER ECDSA signature, as
// KMS returns it) over the exact statement bytes, then parses and validates
// the statement. Nothing in the statement is trusted before the signature
// verifies.
func VerifyStatement(statement, sigB64 []byte, pub *ecdsa.PublicKey) (*Statement, error) {
	if len(statement) > maxStatementBytes {
		return nil, errors.New("manifest statement: too large")
	}
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sigB64)))
	if err != nil {
		return nil, fmt.Errorf("manifest statement: signature is not base64: %w", err)
	}
	digest := sha256.Sum256(statement)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil, ErrBadSignature
	}

	var s Statement
	dec := json.NewDecoder(bytes.NewReader(statement))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("manifest statement: %w", err)
	}
	if dec.More() {
		return nil, errors.New("manifest statement: trailing data")
	}
	if err := s.validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Statement) validate() error {
	switch {
	case s.Schema != StatementSchema:
		return fmt.Errorf("manifest statement: schema %q, want %q", s.Schema, StatementSchema)
	case !reAMI.MatchString(s.AMIID):
		return fmt.Errorf("manifest statement: bad ami_id %q", s.AMIID)
	case !reSnap.MatchString(s.SnapshotID):
		return fmt.Errorf("manifest statement: bad snapshot_id %q", s.SnapshotID)
	case s.Region == "":
		return errors.New("manifest statement: empty region")
	case !reSHA256.MatchString(s.ManifestSHA256),
		!reSHA256.MatchString(s.ManifestGzSHA256),
		!reSHA256.MatchString(s.EntriesSHA256):
		return errors.New("manifest statement: hashes must be 64 lowercase hex digits")
	case s.KeyID == "":
		return errors.New("manifest statement: empty key_id")
	}
	return nil
}

// manifestHeader is the part of the manifest the statement is checked
// against. Entries are read later by the verifier, from the same bytes.
type manifestHeader struct {
	Schema        string `json:"schema"`
	EntriesSHA256 string `json:"entries_sha256"`
	Source        struct {
		AMIID      string `json:"ami_id"`
		SnapshotID string `json:"snapshot_id"`
		Region     string `json:"region"`
	} `json:"source"`
}

// CheckManifestGz checks the gzipped manifest against the statement and
// returns the uncompressed manifest JSON. Both the .gz bytes and the
// uncompressed bytes must match their signed hashes, and the manifest must
// name the same AMI, snapshot, region and entries digest.
func (s *Statement) CheckManifestGz(gz []byte) ([]byte, error) {
	if got := sum(gz); got != s.ManifestGzSHA256 {
		return nil, fmt.Errorf("manifest: .gz sha256 %s, statement says %s", got, s.ManifestGzSHA256)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, maxManifestJSONSize+1))
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if len(raw) > maxManifestJSONSize {
		return nil, errors.New("manifest: too large")
	}
	if got := sum(raw); got != s.ManifestSHA256 {
		return nil, fmt.Errorf("manifest: sha256 %s, statement says %s", got, s.ManifestSHA256)
	}
	var h manifestHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	switch {
	case h.Schema != ManifestSchema:
		return nil, fmt.Errorf("manifest: schema %q, want %q", h.Schema, ManifestSchema)
	case h.Source.AMIID != s.AMIID || h.Source.SnapshotID != s.SnapshotID || h.Source.Region != s.Region:
		return nil, fmt.Errorf("manifest: built from %s/%s in %s, statement is for %s/%s in %s",
			h.Source.AMIID, h.Source.SnapshotID, h.Source.Region, s.AMIID, s.SnapshotID, s.Region)
	case h.EntriesSHA256 != s.EntriesSHA256:
		return nil, fmt.Errorf("manifest: entries_sha256 %s, statement says %s", h.EntriesSHA256, s.EntriesSHA256)
	}
	return raw, nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
