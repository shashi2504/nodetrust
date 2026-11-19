package attest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Object attributes (Part 2, 8.3.2).
const (
	AttrFixedTPM            = 1 << 1
	AttrSTClear             = 1 << 2
	AttrFixedParent         = 1 << 4
	AttrSensitiveDataOrigin = 1 << 5
	AttrUserWithAuth        = 1 << 6
	AttrAdminWithPolicy     = 1 << 7
	AttrNoDA                = 1 << 10
	AttrRestricted          = 1 << 16
	AttrDecrypt             = 1 << 17
	AttrSign                = 1 << 18
)

// Public is a parsed TPMT_PUBLIC.
type Public struct {
	Type       uint16
	NameAlg    uint16
	Attributes uint32
	AuthPolicy []byte
	SymAlg     uint16 // symmetric algorithm of a storage key (AES) or algNull
	SymBits    uint16
	SymMode    uint16
	Scheme     uint16 // signing scheme (ECDSA, RSASSA) or algNull
	SchemeHash uint16
	Key        crypto.PublicKey // *rsa.PublicKey or *ecdsa.PublicKey
	Raw        []byte           // the exact TPMT_PUBLIC bytes
}

// Name is the TPM name of the object: nameAlg || H_nameAlg(TPMT_PUBLIC).
func (p *Public) Name() ([]byte, error) {
	h, err := hashFor(p.NameAlg)
	if err != nil {
		return nil, err
	}
	d := h.New()
	d.Write(p.Raw)
	return append(binary.BigEndian.AppendUint16(nil, p.NameAlg), d.Sum(nil)...), nil
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n > len(r.b) {
		r.err = errors.New("truncated structure")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint8 {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}

func (r *reader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

func (r *reader) u64() uint64 {
	b := r.take(8)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

func (r *reader) tpm2b() []byte {
	n := r.u16()
	return r.take(int(n))
}

// ParsePublic parses TPMT_PUBLIC bytes (the contents of a TPM2B_PUBLIC).
// Only RSA and NIST P-256/P-384 ECC keys are accepted.
func ParsePublic(raw []byte) (*Public, error) {
	r := &reader{b: raw}
	p := &Public{Raw: append([]byte(nil), raw...)}
	p.Type = r.u16()
	p.NameAlg = r.u16()
	p.Attributes = r.u32()
	p.AuthPolicy = r.tpm2b()

	symDef := func() {
		p.SymAlg = r.u16()
		if p.SymAlg != algNull {
			p.SymBits = r.u16()
			p.SymMode = r.u16()
		}
	}
	scheme := func() {
		p.Scheme = r.u16()
		if p.Scheme != algNull {
			if p.Scheme != algECDSA && p.Scheme != algRSASSA && p.Scheme != algRSAPSS {
				r.err = fmt.Errorf("unsupported scheme 0x%04x", p.Scheme)
				return
			}
			p.SchemeHash = r.u16()
		}
	}

	switch p.Type {
	case algRSA:
		symDef()
		scheme()
		bits := r.u16()
		exp := r.u32()
		n := r.tpm2b()
		if r.err != nil {
			return nil, fmt.Errorf("TPMT_PUBLIC: %w", r.err)
		}
		if exp == 0 {
			exp = 65537
		}
		if int(bits) != len(n)*8 || bits < 2048 {
			return nil, fmt.Errorf("TPMT_PUBLIC: RSA modulus is %d bytes for %d bits", len(n), bits)
		}
		p.Key = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exp)}
	case algECC:
		symDef()
		scheme()
		curveID := r.u16()
		kdf := r.u16()
		if kdf != algNull {
			r.u16() // KDF hash
		}
		x := r.tpm2b()
		y := r.tpm2b()
		if r.err != nil {
			return nil, fmt.Errorf("TPMT_PUBLIC: %w", r.err)
		}
		var c elliptic.Curve
		switch curveID {
		case eccNistP256:
			c = elliptic.P256()
		case eccNistP384:
			c = elliptic.P384()
		default:
			return nil, fmt.Errorf("TPMT_PUBLIC: unsupported curve 0x%04x", curveID)
		}
		k, err := ecdsaKey(c, x, y)
		if err != nil {
			return nil, fmt.Errorf("TPMT_PUBLIC: %w", err)
		}
		p.Key = k
	default:
		return nil, fmt.Errorf("TPMT_PUBLIC: unsupported key type 0x%04x", p.Type)
	}
	if len(r.b) != 0 {
		return nil, errors.New("TPMT_PUBLIC: trailing bytes")
	}
	if _, err := hashFor(p.NameAlg); err != nil || p.NameAlg == algSHA1 {
		return nil, fmt.Errorf("TPMT_PUBLIC: name algorithm 0x%04x not accepted", p.NameAlg)
	}
	return p, nil
}

func ecdsaKey(c elliptic.Curve, x, y []byte) (*ecdsa.PublicKey, error) {
	size := (c.Params().BitSize + 7) / 8
	if len(x) > size || len(y) > size {
		return nil, errors.New("ECC point coordinate too long")
	}
	// Uncompressed SEC 1 encoding, so the standard library checks the point
	// is on the curve.
	enc := make([]byte, 1+2*size)
	enc[0] = 4
	copy(enc[1+size-len(x):1+size], x)
	copy(enc[1+2*size-len(y):], y)
	//nolint:staticcheck // Unmarshal is the stdlib way to validate a raw point
	px, py := elliptic.Unmarshal(c, enc)
	if px == nil {
		return nil, errors.New("ECC point is not on the curve")
	}
	return &ecdsa.PublicKey{Curve: c, X: px, Y: py}, nil
}

// CheckAK checks that a public area is suitable as an attestation key: a
// restricted signing key created inside this TPM that never leaves it.
func (p *Public) CheckAK() error {
	want := uint32(AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrRestricted | AttrSign)
	if p.Attributes&want != want {
		return fmt.Errorf("AK attributes 0x%08x lack fixedTPM, fixedParent, sensitiveDataOrigin, restricted or sign", p.Attributes)
	}
	if p.Attributes&AttrDecrypt != 0 {
		return errors.New("AK must not be a decryption key")
	}
	switch p.Type {
	case algECC:
		if p.Scheme != algECDSA {
			return errors.New("ECC AK must use ECDSA")
		}
	case algRSA:
		if p.Scheme != algRSASSA && p.Scheme != algRSAPSS {
			return errors.New("RSA AK must use RSASSA or RSAPSS")
		}
	}
	if p.SchemeHash != algSHA256 && p.SchemeHash != algSHA384 {
		return fmt.Errorf("AK signing hash 0x%04x not accepted", p.SchemeHash)
	}
	return nil
}

// SameKey reports whether the public area holds the given public key (for
// example the EK from the EC2 GetInstanceTpmEkPub API).
func (p *Public) SameKey(k crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	e, ok := p.Key.(equaler)
	return ok && e.Equal(k)
}

// --- marshalling, for tests and for MakeCredential's ECC point ---------------

func appendTPM2B(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

// MarshalECCPublic builds a TPMT_PUBLIC for an ECC key. Used by tests and by
// tools that need the bytes of a known template.
func MarshalECCPublic(nameAlg uint16, attrs uint32, authPolicy []byte, symAlg, symBits, symMode, scheme, schemeHash uint16, k *ecdsa.PublicKey) []byte {
	b := binary.BigEndian.AppendUint16(nil, algECC)
	b = binary.BigEndian.AppendUint16(b, nameAlg)
	b = binary.BigEndian.AppendUint32(b, attrs)
	b = appendTPM2B(b, authPolicy)
	b = binary.BigEndian.AppendUint16(b, symAlg)
	if symAlg != algNull {
		b = binary.BigEndian.AppendUint16(b, symBits)
		b = binary.BigEndian.AppendUint16(b, symMode)
	}
	b = binary.BigEndian.AppendUint16(b, scheme)
	if scheme != algNull {
		b = binary.BigEndian.AppendUint16(b, schemeHash)
	}
	curve := uint16(eccNistP256)
	if k.Curve == elliptic.P384() {
		curve = eccNistP384
	}
	b = binary.BigEndian.AppendUint16(b, curve)
	b = binary.BigEndian.AppendUint16(b, algNull) // KDF
	size := (k.Curve.Params().BitSize + 7) / 8
	b = appendTPM2B(b, k.X.FillBytes(make([]byte, size)))
	b = appendTPM2B(b, k.Y.FillBytes(make([]byte, size)))
	return b
}

// MarshalRSAPublic builds a TPMT_PUBLIC for an RSA key.
func MarshalRSAPublic(nameAlg uint16, attrs uint32, authPolicy []byte, symAlg, symBits, symMode, scheme, schemeHash uint16, k *rsa.PublicKey) []byte {
	b := binary.BigEndian.AppendUint16(nil, algRSA)
	b = binary.BigEndian.AppendUint16(b, nameAlg)
	b = binary.BigEndian.AppendUint32(b, attrs)
	b = appendTPM2B(b, authPolicy)
	b = binary.BigEndian.AppendUint16(b, symAlg)
	if symAlg != algNull {
		b = binary.BigEndian.AppendUint16(b, symBits)
		b = binary.BigEndian.AppendUint16(b, symMode)
	}
	b = binary.BigEndian.AppendUint16(b, scheme)
	if scheme != algNull {
		b = binary.BigEndian.AppendUint16(b, schemeHash)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(k.N.BitLen()))
	exp := uint32(k.E)
	if exp == 65537 {
		exp = 0
	}
	b = binary.BigEndian.AppendUint32(b, exp)
	return appendTPM2B(b, k.N.Bytes())
}

// Exported algorithm IDs for callers building templates.
const (
	AlgRSA    = algRSA
	AlgECC    = algECC
	AlgAES    = algAES
	AlgCFB    = algCFB
	AlgNull   = algNull
	AlgSHA256 = algSHA256
	AlgECDSA  = algECDSA
	AlgRSASSA = algRSASSA
)
