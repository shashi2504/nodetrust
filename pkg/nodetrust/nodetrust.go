// Package nodetrust is the trust state the verifier publishes into the
// cluster (blueprint 8.1): one cluster-scoped NodeTrust object per worker,
// named by its instance ID. Every update carries the verifier's signature
// over the exact bytes of the state, so a reader (the trust controller,
// Phase 5) can tell a real update from one written by anyone else, and a
// sequence number, so an old update cannot be replayed. The fields shown by
// kubectl are copies for people; only the signed payload counts.
package nodetrust

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"nodetrust/pkg/trust"
)

// API group and version of the NodeTrust resource.
const (
	Group      = "trust.k8s-attest.io"
	Version    = "v1alpha1"
	APIVersion = Group + "/" + Version
	Kind       = "NodeTrust"
	Resource   = "nodetrusts"
	Format     = "nodetrust-state/1"
)

// State is what the verifier signs: its view of one worker.
type State struct {
	Format     string    `json:"format"`
	InstanceID string    `json:"instance_id"`
	AMI        string    `json:"ami"`
	Seq        uint64    `json:"seq"` // increases with every update of this node
	IssuedAt   time.Time `json:"issued_at"`

	Tier             string             `json:"tier"`
	Score            float64            `json:"score"`
	Components       map[string]float64 `json:"components,omitempty"`
	Critical         bool               `json:"critical"`
	Findings         []trust.Finding    `json:"findings,omitempty"`
	Unattested       bool               `json:"unattested"`
	UnattestedReason string             `json:"unattested_reason,omitempty"`
	Files            []trust.File       `json:"files,omitempty"`
	Drift            []trust.Drop       `json:"drift,omitempty"`
	LastAttestation  time.Time          `json:"last_attestation,omitempty"`
	ResetCount       uint32             `json:"reset_count"` // the TPM's boot counter
	Reboots          int                `json:"reboots"`
	State            string             `json:"state"` // the verifier's last cycle: verified, unreachable, outage, ...
}

// Signed is a state with the verifier's signature.
type Signed struct {
	Payload   string `json:"payload"`   // base64 of the exact JSON bytes signed
	Signature string `json:"signature"` // base64 ASN.1 ECDSA signature over SHA-256(payload bytes)
	KeyID     string `json:"keyID"`     // first 16 hex of SHA-256 of the public key (DER SPKI)
}

// KeyID names a public key.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:8]), nil
}

// Sign signs a state.
func Sign(key *ecdsa.PrivateKey, st *State) (*Signed, error) {
	st.Format = Format
	b, err := json.Marshal(st)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(b)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	id, err := KeyID(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signed{Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(sig), KeyID: id}, nil
}

// Verify checks a signed state against the pinned public key and returns
// the state. It does not judge freshness or order; see Check.
func Verify(pub *ecdsa.PublicKey, s *Signed) (*State, error) {
	if s == nil || s.Payload == "" || s.Signature == "" {
		return nil, errors.New("nodetrust: unsigned")
	}
	id, err := KeyID(pub)
	if err != nil {
		return nil, err
	}
	if s.KeyID != id {
		return nil, fmt.Errorf("nodetrust: signed with key %q, want %q", s.KeyID, id)
	}
	b, err := base64.StdEncoding.DecodeString(s.Payload)
	if err != nil {
		return nil, fmt.Errorf("nodetrust: payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil {
		return nil, fmt.Errorf("nodetrust: signature: %w", err)
	}
	h := sha256.Sum256(b)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return nil, errors.New("nodetrust: signature does not verify")
	}
	var st State
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, fmt.Errorf("nodetrust: payload: %w", err)
	}
	if st.Format != Format {
		return nil, fmt.Errorf("nodetrust: format %q", st.Format)
	}
	return &st, nil
}

// Check verifies a signed state for the object it was found in: the
// signature, that it is about that instance, that it is newer than the last
// sequence number the reader accepted (lastSeq; 0 for none), and that it is
// not older than maxAge at now (0 skips the age check).
func Check(pub *ecdsa.PublicKey, s *Signed, name string, lastSeq uint64, now time.Time, maxAge time.Duration) (*State, error) {
	st, err := Verify(pub, s)
	if err != nil {
		return nil, err
	}
	switch {
	case st.InstanceID != name:
		return nil, fmt.Errorf("nodetrust: object %s holds the state of %s", name, st.InstanceID)
	case st.Seq <= lastSeq:
		return nil, fmt.Errorf("nodetrust: sequence %d is not after %d (replayed or old)", st.Seq, lastSeq)
	case maxAge > 0 && now.Sub(st.IssuedAt) > maxAge:
		return nil, fmt.Errorf("nodetrust: issued %s ago", now.Sub(st.IssuedAt).Round(time.Second))
	}
	return st, nil
}

// ParsePrivateKey reads an ECDSA private key PEM (SEC 1 or PKCS #8).
func ParsePrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("nodetrust: no PEM key")
	}
	if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("nodetrust: key: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("nodetrust: not an ECDSA key")
	}
	return ek, nil
}

// ParsePublicKey reads an ECDSA public key PEM (PKIX).
func ParsePublicKey(b []byte) (*ecdsa.PublicKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("nodetrust: no PEM key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	ek, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("nodetrust: not an ECDSA key")
	}
	return ek, nil
}

// Object is the NodeTrust object for a signed state. The status fields
// besides "signed" are copies for kubectl; readers must use the payload.
func Object(st *State, s *Signed) map[string]any {
	return map[string]any{
		"apiVersion": APIVersion,
		"kind":       Kind,
		"metadata":   map[string]any{"name": st.InstanceID},
		"spec":       map[string]any{"instanceID": st.InstanceID},
		"status": map[string]any{
			"signed":     s,
			"tier":       st.Tier,
			"score":      st.Score,
			"critical":   st.Critical,
			"unattested": st.Unattested,
			"seq":        st.Seq,
			"issuedAt":   st.IssuedAt.UTC().Format(time.RFC3339),
		},
	}
}
