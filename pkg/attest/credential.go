package attest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Credential is the output of MakeCredential, in the form TPM2_ActivateCredential
// takes it: the contents of a TPM2B_ID_OBJECT and of a TPM2B_ENCRYPTED_SECRET.
type Credential struct {
	IDObject        []byte // credentialBlob: TPM2B(outer HMAC) || encrypted identity
	EncryptedSecret []byte // RSA-OAEP of the seed, or a TPMS_ECC_POINT for ECC
}

// MakeCredential does in software what TPM2_MakeCredential does (Part 1,
// 24 "Credential Protection"): it protects secret so that only the TPM that
// holds the private part of ek, and only for a loaded object with the given
// name, can recover it with TPM2_ActivateCredential.
//
// The verifier uses it at enrollment with the EK from the EC2 API and the
// name of the AK the agent presents. If the agent can return the secret, the
// AK is in the same TPM as that EK.
func MakeCredential(rng io.Reader, ek *Public, akName, secret []byte) (*Credential, error) {
	if rng == nil {
		rng = rand.Reader
	}
	h, err := hashFor(ek.NameAlg)
	if err != nil {
		return nil, err
	}
	if ek.Attributes&(AttrRestricted|AttrDecrypt) != AttrRestricted|AttrDecrypt {
		return nil, errors.New("make credential: EK is not a restricted decryption key")
	}
	if ek.SymAlg != algAES || ek.SymMode != algCFB {
		return nil, fmt.Errorf("make credential: EK symmetric 0x%04x/0x%04x, want AES-CFB", ek.SymAlg, ek.SymMode)
	}
	if len(secret) > h.Size() {
		return nil, fmt.Errorf("make credential: secret longer than %d bytes", h.Size())
	}

	// 1. A seed, shared with the TPM through the EK.
	var seed, encSecret []byte
	switch k := ek.Key.(type) {
	case *rsa.PublicKey:
		seed = make([]byte, h.Size())
		if _, err := io.ReadFull(rng, seed); err != nil {
			return nil, err
		}
		encSecret, err = rsa.EncryptOAEP(h.New(), rng, k, seed, []byte("IDENTITY\x00"))
		if err != nil {
			return nil, fmt.Errorf("make credential: %w", err)
		}
	case *ecdsa.PublicKey:
		seed, encSecret, err = eccSeed(rng, h.Size()*8, ek, k)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("make credential: unsupported EK key type")
	}

	// 2. Encrypt the secret (as a TPM2B_DIGEST) with a key bound to the AK name.
	symKey := kdfa(h, seed, "STORAGE", akName, nil, int(ek.SymBits))
	block, err := aes.NewCipher(symKey)
	if err != nil {
		return nil, fmt.Errorf("make credential: %w", err)
	}
	plain := appendTPM2B(nil, secret)
	encIdentity := make([]byte, len(plain))
	cipher.NewCFBEncrypter(block, make([]byte, block.BlockSize())).XORKeyStream(encIdentity, plain)

	// 3. Outer HMAC over the encrypted identity and the AK name.
	hmacKey := kdfa(h, seed, "INTEGRITY", nil, nil, h.Size()*8)
	m := hmac.New(h.New, hmacKey)
	m.Write(encIdentity)
	m.Write(akName)

	return &Credential{
		IDObject:        append(appendTPM2B(nil, m.Sum(nil)), encIdentity...),
		EncryptedSecret: encSecret,
	}, nil
}

// eccSeed derives the seed with one-pass ECDH (Part 1, C.6.4): an ephemeral
// key pair, Z = x-coordinate of the shared point, seed = KDFe(Z, "IDENTITY",
// ephemeral x, EK x). The encrypted secret is the ephemeral public point.
func eccSeed(rng io.Reader, bits int, ek *Public, k *ecdsa.PublicKey) (seed, point []byte, err error) {
	var curve ecdh.Curve
	switch k.Curve {
	case elliptic.P256():
		curve = ecdh.P256()
	case elliptic.P384():
		curve = ecdh.P384()
	default:
		return nil, nil, errors.New("make credential: unsupported EK curve")
	}
	ekECDH, err := k.ECDH()
	if err != nil {
		return nil, nil, fmt.Errorf("make credential: %w", err)
	}
	eph, err := curve.GenerateKey(rng)
	if err != nil {
		return nil, nil, err
	}
	z, err := eph.ECDH(ekECDH)
	if err != nil {
		return nil, nil, err
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	ephRaw := eph.PublicKey().Bytes() // 0x04 || X || Y
	ephX, ephY := ephRaw[1:1+size], ephRaw[1+size:]
	ekX := k.X.FillBytes(make([]byte, size))
	h, _ := hashFor(ek.NameAlg)
	seed = kdfe(h, z, "IDENTITY", ephX, ekX, bits)
	point = appendTPM2B(appendTPM2B(nil, ephX), ephY)
	return seed, point, nil
}

// decryptCredential is ActivateCredential's inverse operation, done in
// software with the EK private key. Tests use it to check MakeCredential;
// the real check is the TPM (simulator test and NitroTPM).
func decryptCredential(ek *Public, seed, akName []byte, c *Credential) ([]byte, error) {
	h, err := hashFor(ek.NameAlg)
	if err != nil {
		return nil, err
	}
	r := &reader{b: c.IDObject}
	outerHMAC := r.tpm2b()
	encIdentity := r.b
	if r.err != nil {
		return nil, r.err
	}
	m := hmac.New(h.New, kdfa(h, seed, "INTEGRITY", nil, nil, h.Size()*8))
	m.Write(encIdentity)
	m.Write(akName)
	if !hmac.Equal(m.Sum(nil), outerHMAC) {
		return nil, errors.New("integrity check failed")
	}
	block, err := aes.NewCipher(kdfa(h, seed, "STORAGE", akName, nil, int(ek.SymBits)))
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(encIdentity))
	cipher.NewCFBDecrypter(block, make([]byte, block.BlockSize())).XORKeyStream(plain, encIdentity)
	if len(plain) < 2 || int(binary.BigEndian.Uint16(plain)) != len(plain)-2 {
		return nil, errors.New("bad identity")
	}
	return plain[2:], nil
}
