// Package agent is the node side of attestation (blueprint Phase 3). This
// file is the TPM layer: the endorsement key, the attestation key, credential
// activation and quotes. The verifier side of every operation is in
// pkg/attest, which needs no TPM.
//
// Both keys are primary keys created from fixed templates, so the TPM
// derives the same key from its hierarchy seed every time: the agent stores
// no key material on disk. The EK comes from the TCG RSA-2048 EK template,
// which on NitroTPM gives the key the EC2 GetInstanceTpmEkPub API returns
// (checked in Phase 1). The AK is a restricted ECDSA P-256 signing key in the
// endorsement hierarchy; a restricted key only signs data the TPM produced itself,
// so even root on the node cannot make it sign a forged quote.
package agent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// DefaultDevice is the kernel's TPM resource manager.
const DefaultDevice = "/dev/tpmrm0"

// QuotePCRs are the PCRs the agent quotes: the boot chain (0-9) and IMA (10).
var QuotePCRs = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

// AKTemplate is the attestation key template.
var AKTemplate = tpm2.TPMTPublic{
	Type:    tpm2.TPMAlgECC,
	NameAlg: tpm2.TPMAlgSHA256,
	ObjectAttributes: tpm2.TPMAObject{
		FixedTPM:            true,
		FixedParent:         true,
		SensitiveDataOrigin: true,
		UserWithAuth:        true,
		NoDA:                true,
		Restricted:          true,
		SignEncrypt:         true,
	},
	Parameters: tpm2.NewTPMUPublicParms(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCParms{
			Scheme: tpm2.TPMTECCScheme{
				Scheme: tpm2.TPMAlgECDSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgECDSA,
					&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
				),
			},
			CurveID: tpm2.TPMECCNistP256,
		},
	),
	Unique: tpm2.NewTPMUPublicID(
		tpm2.TPMAlgECC,
		&tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		},
	),
}

// Key is a loaded primary key.
type Key struct {
	Handle tpm2.TPMHandle
	Name   tpm2.TPM2BName
	Public []byte // TPMT_PUBLIC, as pkg/attest.ParsePublic reads it
}

// TPM wraps a TPM connection with the EK and AK loaded.
type TPM struct {
	t      transport.TPM
	closer func() error
	EK     Key
	AK     Key
}

// Open opens the TPM device and loads both keys. A device of the form
// "tcp:HOST:PORT" connects to a software TPM (swtpm) instead; that is for
// development and tests only, never for a node.
func Open(device string) (*TPM, error) {
	var t transport.TPMCloser
	var err error
	if addr, ok := strings.CutPrefix(device, "tcp:"); ok {
		t, err = dialSWTPM(addr)
	} else {
		t, err = linuxtpm.Open(device)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", device, err)
	}
	a, err := New(t)
	if err != nil {
		t.Close()
		return nil, err
	}
	a.closer = t.Close
	return a, nil
}

// New loads both keys on an open TPM (tests pass the simulator). Close
// flushes them; it does not close t unless Open created it.
func New(t transport.TPM) (*TPM, error) {
	a := &TPM{t: t}
	var err error
	if a.EK, err = a.createPrimary(tpm2.TPMRHEndorsement, tpm2.RSAEKTemplate); err != nil {
		return nil, fmt.Errorf("create EK: %w", err)
	}
	// The AK lives in the endorsement hierarchy: for a key in the owner
	// hierarchy the TPM obfuscates resetCount, restartCount and the firmware
	// version in quotes (Part 1, "Privacy"), and the verifier needs the real
	// resetCount to see reboots.
	if a.AK, err = a.createPrimary(tpm2.TPMRHEndorsement, AKTemplate); err != nil {
		a.flush(a.EK.Handle)
		return nil, fmt.Errorf("create AK: %w", err)
	}
	return a, nil
}

func (a *TPM) createPrimary(h tpm2.TPMHandle, tmpl tpm2.TPMTPublic) (Key, error) {
	rsp, err := tpm2.CreatePrimary{PrimaryHandle: h, InPublic: tpm2.New2B(tmpl)}.Execute(a.t)
	if err != nil {
		return Key{}, err
	}
	return Key{Handle: rsp.ObjectHandle, Name: rsp.Name, Public: rsp.OutPublic.Bytes()}, nil
}

func (a *TPM) flush(h tpm2.TPMHandle) {
	_, _ = tpm2.FlushContext{FlushHandle: h}.Execute(a.t)
}

// Close flushes both keys and closes the device if Open opened it.
func (a *TPM) Close() error {
	a.flush(a.AK.Handle)
	a.flush(a.EK.Handle)
	if a.closer != nil {
		return a.closer()
	}
	return nil
}

// ekPolicy satisfies the TCG EK policy, PolicySecret(TPM_RH_ENDORSEMENT),
// with the (empty) endorsement hierarchy auth.
func ekPolicy(t transport.TPM, handle tpm2.TPMISHPolicy, nonceTPM tpm2.TPM2BNonce) error {
	_, err := tpm2.PolicySecret{
		AuthHandle:    tpm2.TPMRHEndorsement,
		PolicySession: handle,
		NonceTPM:      nonceTPM,
	}.Execute(t)
	return err
}

// ActivateCredential recovers the secret the verifier encrypted with
// attest.MakeCredential for this TPM's EK and this AK. The TPM only releases
// it if the AK named in the credential is loaded here.
func (a *TPM) ActivateCredential(idObject, encSecret []byte) ([]byte, error) {
	rsp, err := tpm2.ActivateCredential{
		ActivateHandle: tpm2.NamedHandle{Handle: a.AK.Handle, Name: a.AK.Name},
		KeyHandle: tpm2.AuthHandle{
			Handle: a.EK.Handle,
			Name:   a.EK.Name,
			Auth:   tpm2.Policy(tpm2.TPMAlgSHA256, 16, ekPolicy),
		},
		CredentialBlob: tpm2.TPM2BIDObject{Buffer: idObject},
		Secret:         tpm2.TPM2BEncryptedSecret{Buffer: encSecret},
	}.Execute(a.t)
	if err != nil {
		return nil, fmt.Errorf("activate credential: %w", err)
	}
	return rsp.CertInfo.Buffer, nil
}

// Quote is a signed quote with the PCR values it covers.
type Quote struct {
	Attest    []byte         // TPMS_ATTEST
	Signature []byte         // TPMT_SIGNATURE
	PCRs      map[int][]byte // SHA-256 values of QuotePCRs at quote time
}

// Quote signs the SHA-256 PCRs in QuotePCRs together with the verifier's
// nonce. The PCR values are read before and after the quote; if a PCR moved
// in between (IMA extends PCR 10 all the time), it tries again, so the
// values returned are the ones the quote covers.
func (a *TPM) Quote(nonce []byte) (*Quote, error) {
	if len(nonce) == 0 || len(nonce) > 64 {
		return nil, errors.New("quote: nonce must be 1-64 bytes")
	}
	sel := pcrSelection(QuotePCRs)
	for try := 0; try < 10; try++ {
		before, err := a.readPCRs(QuotePCRs)
		if err != nil {
			return nil, err
		}
		rsp, err := tpm2.Quote{
			SignHandle:     tpm2.NamedHandle{Handle: a.AK.Handle, Name: a.AK.Name},
			QualifyingData: tpm2.TPM2BData{Buffer: nonce},
			InScheme:       tpm2.TPMTSigScheme{Scheme: tpm2.TPMAlgNull},
			PCRSelect:      sel,
		}.Execute(a.t)
		if err != nil {
			return nil, fmt.Errorf("quote: %w", err)
		}
		after, err := a.readPCRs(QuotePCRs)
		if err != nil {
			return nil, err
		}
		if samePCRs(before, after) {
			return &Quote{
				Attest:    rsp.Quoted.Bytes(),
				Signature: tpm2.Marshal(rsp.Signature),
				PCRs:      after,
			}, nil
		}
	}
	return nil, errors.New("quote: PCRs kept changing during the quote; try again")
}

func pcrSelection(pcrs []int) tpm2.TPMLPCRSelection {
	idx := make([]uint, len(pcrs))
	for i, p := range pcrs {
		idx[i] = uint(p)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{{
		Hash:      tpm2.TPMAlgSHA256,
		PCRSelect: tpm2.PCClientCompatible.PCRs(idx...),
	}}}
}

// readPCRs reads SHA-256 PCRs. The TPM returns at most 8 per call, and
// returns them in ascending order of the ones it chose to include.
func (a *TPM) readPCRs(pcrs []int) (map[int][]byte, error) {
	out := map[int][]byte{}
	remaining := append([]int(nil), pcrs...)
	for len(remaining) > 0 {
		rsp, err := tpm2.PCRRead{PCRSelectionIn: pcrSelection(remaining)}.Execute(a.t)
		if err != nil {
			return nil, fmt.Errorf("read PCRs: %w", err)
		}
		var got []int
		for _, s := range rsp.PCRSelectionOut.PCRSelections {
			for byteIdx, bits := range s.PCRSelect {
				for bit := 0; bit < 8; bit++ {
					if bits&(1<<bit) != 0 {
						got = append(got, byteIdx*8+bit)
					}
				}
			}
		}
		if len(got) == 0 || len(got) != len(rsp.PCRValues.Digests) {
			return nil, errors.New("read PCRs: TPM returned no or mismatched values")
		}
		for i, p := range got {
			out[p] = rsp.PCRValues.Digests[i].Buffer
		}
		var next []int
		for _, p := range remaining {
			if _, ok := out[p]; !ok {
				next = append(next, p)
			}
		}
		remaining = next
	}
	return out, nil
}

func samePCRs(a, b map[int][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if string(b[k]) != string(v) {
			return false
		}
	}
	return true
}

// swtpm is a raw TPM command channel over TCP (swtpm's --server type=tcp).
type swtpm struct{ c net.Conn }

func dialSWTPM(addr string) (transport.TPMCloser, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &swtpm{c: c}, nil
}

func (s *swtpm) Send(cmd []byte) ([]byte, error) {
	if _, err := s.c.Write(cmd); err != nil {
		return nil, err
	}
	hdr := make([]byte, 10) // tag, size, response code
	if _, err := io.ReadFull(s.c, hdr); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(hdr[2:6])
	if size < 10 || size > 1<<20 {
		return nil, fmt.Errorf("swtpm: bad response size %d", size)
	}
	rsp := make([]byte, size)
	copy(rsp, hdr)
	if _, err := io.ReadFull(s.c, rsp[10:]); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (s *swtpm) Close() error { return s.c.Close() }
