// Package attest is the verifier's side of TPM 2.0 attestation (blueprint
// Phase 3): parsing TPM structures, software MakeCredential for enrollment,
// and quote verification. It uses the Go standard library only, so the
// verifier never needs a TPM or a TPM library; the agent (pkg/agent) talks
// to the TPM.
//
// References are to the TPM 2.0 Library specification, Part 1 (architecture)
// and Part 2 (structures).
package attest

import (
	"crypto"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
)

// TPM algorithm IDs (Part 2, 6.3).
const (
	algRSA       = 0x0001
	algSHA1      = 0x0004
	algHMAC      = 0x0005
	algAES       = 0x0006
	algSHA256    = 0x000B
	algSHA384    = 0x000C
	algSHA512    = 0x000D
	algNull      = 0x0010
	algRSASSA    = 0x0014
	algRSAPSS    = 0x0016
	algECDSA     = 0x0018
	algECC       = 0x0023
	algCFB       = 0x0043
	eccNistP256  = 0x0003
	eccNistP384  = 0x0004
	attestMagic  = 0xFF544347 // TPM_GENERATED_VALUE
	stAttestQuot = 0x8018     // TPM_ST_ATTEST_QUOTE
)

func hashFor(alg uint16) (crypto.Hash, error) {
	switch alg {
	case algSHA1:
		return crypto.SHA1, nil
	case algSHA256:
		return crypto.SHA256, nil
	case algSHA384:
		return crypto.SHA384, nil
	case algSHA512:
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported hash algorithm 0x%04x", alg)
}

// kdfa is KDFa from Part 1, 11.4.10.2: SP 800-108 counter mode with HMAC.
// The label is used with its terminating zero byte.
func kdfa(h crypto.Hash, key []byte, label string, contextU, contextV []byte, bits int) []byte {
	out := make([]byte, 0, (bits+7)/8)
	var buf [4]byte
	for counter := uint32(1); len(out) < (bits+7)/8; counter++ {
		m := hmac.New(h.New, key)
		binary.BigEndian.PutUint32(buf[:], counter)
		m.Write(buf[:])
		m.Write([]byte(label))
		m.Write([]byte{0})
		m.Write(contextU)
		m.Write(contextV)
		binary.BigEndian.PutUint32(buf[:], uint32(bits))
		m.Write(buf[:])
		out = m.Sum(out)
	}
	return out[:(bits+7)/8]
}

// kdfe is KDFe from Part 1, 11.4.10.3: the SP 800-56A concatenation KDF used
// with ECDH. Z is the x-coordinate of the shared point.
func kdfe(h crypto.Hash, z []byte, label string, partyU, partyV []byte, bits int) []byte {
	out := make([]byte, 0, (bits+7)/8)
	var buf [4]byte
	for counter := uint32(1); len(out) < (bits+7)/8; counter++ {
		d := h.New()
		binary.BigEndian.PutUint32(buf[:], counter)
		d.Write(buf[:])
		d.Write(z)
		d.Write([]byte(label))
		d.Write([]byte{0})
		d.Write(partyU)
		d.Write(partyV)
		out = d.Sum(out)
	}
	return out[:(bits+7)/8]
}
