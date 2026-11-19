package attest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

// PCRSelection is one bank of a TPML_PCR_SELECTION.
type PCRSelection struct {
	Hash uint16
	PCRs []int // ascending
}

// QuoteInfo is the parsed TPMS_ATTEST of a quote.
type QuoteInfo struct {
	QualifiedSigner []byte
	ExtraData       []byte // the verifier's nonce
	Clock           uint64
	ResetCount      uint32 // increases on every TPM reset (reboot)
	RestartCount    uint32
	Safe            bool
	FirmwareVersion uint64
	Selection       []PCRSelection
	PCRDigest       []byte
}

// ParseQuote parses TPMS_ATTEST bytes and checks that they are a quote made
// by a TPM (the TPM_GENERATED magic, which a restricted key refuses to sign
// for any data the TPM did not produce itself).
func ParseQuote(attest []byte) (*QuoteInfo, error) {
	r := &reader{b: attest}
	if m := r.u32(); m != attestMagic {
		return nil, fmt.Errorf("attest: magic 0x%08x is not TPM_GENERATED", m)
	}
	if t := r.u16(); t != stAttestQuot {
		return nil, fmt.Errorf("attest: type 0x%04x is not a quote", t)
	}
	q := &QuoteInfo{}
	q.QualifiedSigner = r.tpm2b()
	q.ExtraData = r.tpm2b()
	q.Clock = r.u64()
	q.ResetCount = r.u32()
	q.RestartCount = r.u32()
	q.Safe = r.u8() == 1
	q.FirmwareVersion = r.u64()
	n := r.u32()
	if n > 16 {
		return nil, errors.New("attest: too many PCR banks")
	}
	for i := uint32(0); i < n && r.err == nil; i++ {
		sel := PCRSelection{Hash: r.u16()}
		bitmap := r.take(int(r.u8()))
		for byteIdx, bits := range bitmap {
			for bit := 0; bit < 8; bit++ {
				if bits&(1<<bit) != 0 {
					sel.PCRs = append(sel.PCRs, byteIdx*8+bit)
				}
			}
		}
		q.Selection = append(q.Selection, sel)
	}
	q.PCRDigest = r.tpm2b()
	if r.err != nil {
		return nil, fmt.Errorf("attest: %w", r.err)
	}
	if len(r.b) != 0 {
		return nil, errors.New("attest: trailing bytes")
	}
	return q, nil
}

// VerifyQuote checks a quote end to end:
//
//   - the signature (a TPMT_SIGNATURE) over the attest bytes is valid for ak
//   - the attest bytes are a TPM-generated quote carrying exactly nonce
//   - the quote covers exactly the SHA-256 PCRs in pcrs, and its PCR digest
//     equals SHA-256 over those PCR values in ascending order
//
// pcrs holds the PCR values the agent reported; after VerifyQuote they are
// the TPM's values and can be compared with references (boot chain) or
// replayed against (PCR 10 and the IMA log).
func VerifyQuote(ak *Public, attest, sig, nonce []byte, pcrs map[int][]byte) (*QuoteInfo, error) {
	if err := verifySignature(ak, attest, sig); err != nil {
		return nil, err
	}
	q, err := ParseQuote(attest)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(q.ExtraData, nonce) != 1 || len(nonce) == 0 {
		return nil, errors.New("quote: nonce does not match (stale or replayed quote)")
	}
	if len(q.Selection) != 1 || q.Selection[0].Hash != algSHA256 {
		return nil, errors.New("quote: want exactly one PCR bank, SHA-256")
	}
	want := make([]int, 0, len(pcrs))
	for i := range pcrs {
		want = append(want, i)
	}
	sort.Ints(want)
	if fmt.Sprint(want) != fmt.Sprint(q.Selection[0].PCRs) {
		return nil, fmt.Errorf("quote: covers PCRs %v, values given for %v", q.Selection[0].PCRs, want)
	}
	d := sha256.New()
	for _, i := range want {
		if len(pcrs[i]) != sha256.Size {
			return nil, fmt.Errorf("quote: PCR %d value is %d bytes", i, len(pcrs[i]))
		}
		d.Write(pcrs[i])
	}
	if !bytes.Equal(d.Sum(nil), q.PCRDigest) {
		return nil, errors.New("quote: PCR values do not match the signed PCR digest")
	}
	return q, nil
}

// verifySignature checks a TPMT_SIGNATURE made by ak over data.
func verifySignature(ak *Public, data, sig []byte) error {
	if err := ak.CheckAK(); err != nil {
		return err
	}
	r := &reader{b: sig}
	alg := r.u16()
	hashAlg := r.u16()
	if hashAlg != ak.SchemeHash {
		return fmt.Errorf("signature: hash 0x%04x, AK uses 0x%04x", hashAlg, ak.SchemeHash)
	}
	h, err := hashFor(hashAlg)
	if err != nil {
		return err
	}
	d := h.New()
	d.Write(data)
	digest := d.Sum(nil)
	switch alg {
	case algECDSA:
		rr, ss := r.tpm2b(), r.tpm2b()
		if r.err != nil || len(r.b) != 0 {
			return errors.New("signature: malformed ECDSA signature")
		}
		k, ok := ak.Key.(*ecdsa.PublicKey)
		if !ok || ak.Scheme != algECDSA {
			return errors.New("signature: ECDSA signature from a non-ECDSA AK")
		}
		if !ecdsa.Verify(k, digest, new(big.Int).SetBytes(rr), new(big.Int).SetBytes(ss)) {
			return errors.New("signature: does not verify")
		}
	case algRSASSA, algRSAPSS:
		s := r.tpm2b()
		if r.err != nil || len(r.b) != 0 {
			return errors.New("signature: malformed RSA signature")
		}
		k, ok := ak.Key.(*rsa.PublicKey)
		if !ok || ak.Scheme != alg {
			return errors.New("signature: scheme does not match the AK")
		}
		if alg == algRSASSA {
			err = rsa.VerifyPKCS1v15(k, h, digest, s)
		} else {
			err = rsa.VerifyPSS(k, h, digest, s, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: h})
		}
		if err != nil {
			return errors.New("signature: does not verify")
		}
	default:
		return fmt.Errorf("signature: algorithm 0x%04x not supported", alg)
	}
	return nil
}
