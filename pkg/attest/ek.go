package attest

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// TCGEKPolicy is the authPolicy of the TCG default EK templates:
// TPM2_PolicySecret(TPM_RH_ENDORSEMENT).
var TCGEKPolicy = []byte{
	0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
	0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
}

// ekAttributes are the object attributes of the TCG RSA-2048 EK template.
const ekAttributes = AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy | AttrRestricted | AttrDecrypt

// CheckEK checks that an EK public area presented by an agent is the TCG
// RSA-2048 EK and holds exactly the key the cloud vouches for (on AWS the key
// from ec2:GetInstanceTpmEkPub). Only the TPM holding that key's private part
// can activate a credential made for it.
func (p *Public) CheckEK(trusted crypto.PublicKey) error {
	switch {
	case p.Type != algRSA:
		return errors.New("EK: not an RSA key")
	case p.NameAlg != algSHA256:
		return errors.New("EK: name algorithm is not SHA-256")
	case p.Attributes != ekAttributes:
		return fmt.Errorf("EK: attributes 0x%08x are not the TCG EK template's 0x%08x", p.Attributes, uint32(ekAttributes))
	case !bytes.Equal(p.AuthPolicy, TCGEKPolicy):
		return errors.New("EK: authPolicy is not PolicySecret(endorsement)")
	case p.SymAlg != algAES || p.SymBits != 128 || p.SymMode != algCFB:
		return errors.New("EK: symmetric parameters are not AES-128-CFB")
	}
	if k, ok := p.Key.(*rsa.PublicKey); !ok || k.N.BitLen() != 2048 {
		return errors.New("EK: not an RSA-2048 key")
	}
	if !p.SameKey(trusted) {
		return errors.New("EK: key differs from the one the cloud provider reports for this instance")
	}
	return nil
}

// ParseCloudEK parses an EK public key as EC2 GetInstanceTpmEkPub returns it
// with --key-format der: base64 of a DER SubjectPublicKeyInfo (PKCS #1 is
// accepted too).
func ParseCloudEK(b64 string) (crypto.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("cloud EK: not base64: %w", err)
	}
	if k, err := x509.ParsePKIXPublicKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("cloud EK: neither SubjectPublicKeyInfo nor PKCS #1")
}
