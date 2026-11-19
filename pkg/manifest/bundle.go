package manifest

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
)

// Pins are the keys the verifier is configured with: the manifest signing
// key and the Rekor log key. Nothing about an AMI is trusted unless it
// chains to both.
type Pins struct {
	Signing *ecdsa.PublicKey
	Rekor   *ecdsa.PublicKey
}

// Bundle is what the build pipeline publishes for one AMI.
type Bundle struct {
	Statement  []byte // statement.json
	Signature  []byte // statement.sig (base64 DER)
	Manifest   []byte // manifest.json.gz
	RekorEntry []byte // rekor-entry.json
}

// Trusted is a manifest that passed VerifyBundle.
type Trusted struct {
	Statement *Statement
	Rekor     *RekorResult
	Index     map[string]Entry
}

// VerifyBundle checks signature -> statement -> AMI -> manifest -> Rekor
// entry, the same chain `verifier verify-manifest` checks, and indexes the
// manifest.
func VerifyBundle(b *Bundle, ami string, pins Pins) (*Trusted, error) {
	if pins.Signing == nil || pins.Rekor == nil {
		return nil, errors.New("manifest: signing and Rekor keys must both be pinned")
	}
	s, err := VerifyStatement(b.Statement, b.Signature, pins.Signing)
	if err != nil {
		return nil, err
	}
	if s.AMIID != ami {
		return nil, fmt.Errorf("manifest: statement is for %s, not %s", s.AMIID, ami)
	}
	raw, err := s.CheckManifestGz(b.Manifest)
	if err != nil {
		return nil, err
	}
	uuid, e, err := ParseRekorResponse(b.RekorEntry)
	if err != nil {
		return nil, err
	}
	rr, err := VerifyRekor(uuid, e, b.Statement, b.Signature, pins.Signing, pins.Rekor)
	if err != nil {
		return nil, err
	}
	idx, err := Index(raw)
	if err != nil {
		return nil, err
	}
	return &Trusted{Statement: s, Rekor: rr, Index: idx}, nil
}
