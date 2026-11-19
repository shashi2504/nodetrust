// Package verifier is the verifier's attestation logic (blueprint Phase 3
// and 4): enrollment by credential activation, and quote plus IMA log checks.
// It uses pkg/attest and pkg/ima and never talks to a TPM.
package verifier

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"nodetrust/pkg/attest"
	"nodetrust/pkg/eventlog"
	"nodetrust/pkg/ima"
	"nodetrust/pkg/protocol"
)

// Pending is the verifier's private state between challenge and response.
// It holds the secret, so it never leaves the verifier.
type Pending struct {
	InstanceID string    `json:"instance_id"`
	EKPublic   []byte    `json:"ek_public"`
	AKPublic   []byte    `json:"ak_public"`
	Secret     []byte    `json:"secret"`
	Created    time.Time `json:"created"`
}

// Enrolled is the record of an enrolled node: the AK the verifier will
// accept quotes from, bound to the instance and its cloud-vouched EK.
type Enrolled struct {
	InstanceID string    `json:"instance_id"`
	EKSHA256   string    `json:"ek_spki_sha256"` // SHA-256 of the EK's DER SubjectPublicKeyInfo
	AKPublic   []byte    `json:"ak_public"`
	AKName     string    `json:"ak_name"`
	EnrolledAt time.Time `json:"enrolled_at"`
}

// ChallengeTTL bounds how long a challenge may be answered.
const ChallengeTTL = 5 * time.Minute

// NewChallenge checks an agent's enroll request against the EK the cloud
// provider reports for instanceID (never the instance ID the agent claims)
// and makes the credential challenge.
func NewChallenge(instanceID string, cloudEK crypto.PublicKey, req *protocol.EnrollRequest) (*protocol.Challenge, *Pending, error) {
	if req.Version != protocol.Version {
		return nil, nil, fmt.Errorf("enroll: request version %q, want %q", req.Version, protocol.Version)
	}
	ek, err := attest.ParsePublic(req.EKPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: EK: %w", err)
	}
	if err := ek.CheckEK(cloudEK); err != nil {
		return nil, nil, fmt.Errorf("enroll: %w", err)
	}
	ak, err := attest.ParsePublic(req.AKPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("enroll: AK: %w", err)
	}
	if err := ak.CheckAK(); err != nil {
		return nil, nil, fmt.Errorf("enroll: %w", err)
	}
	akName, err := ak.Name()
	if err != nil {
		return nil, nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, nil, err
	}
	cred, err := attest.MakeCredential(rand.Reader, ek, akName, secret)
	if err != nil {
		return nil, nil, err
	}
	return &protocol.Challenge{Version: protocol.Version, IDObject: cred.IDObject, EncryptedSecret: cred.EncryptedSecret},
		&Pending{InstanceID: instanceID, EKPublic: req.EKPublic, AKPublic: req.AKPublic, Secret: secret, Created: time.Now().UTC()},
		nil
}

// Finish checks the agent's answer. A correct secret proves the AK is in the
// TPM that holds the cloud-vouched EK.
func Finish(p *Pending, resp *protocol.ChallengeResponse, now time.Time) (*Enrolled, error) {
	if now.Sub(p.Created) > ChallengeTTL {
		return nil, errors.New("enroll: challenge expired")
	}
	if resp.Version != protocol.Version {
		return nil, fmt.Errorf("enroll: response version %q", resp.Version)
	}
	if subtle.ConstantTimeCompare(resp.Secret, p.Secret) != 1 {
		return nil, errors.New("enroll: wrong secret; the AK is not in the TPM with this instance's EK")
	}
	ek, err := attest.ParsePublic(p.EKPublic)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(ek.Key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)
	ak, err := attest.ParsePublic(p.AKPublic)
	if err != nil {
		return nil, err
	}
	name, _ := ak.Name()
	return &Enrolled{
		InstanceID: p.InstanceID,
		EKSHA256:   hex.EncodeToString(sum[:]),
		AKPublic:   p.AKPublic,
		AKName:     hex.EncodeToString(name),
		EnrolledAt: now.UTC(),
	}, nil
}

// ReplayState is how far the verifier has checked a node's IMA log in the
// current boot, so the next challenge asks only for what is new (blueprint
// 6.2: an incremental log). It also holds the boot PCRs checked against the
// event log at the start of the boot.
type ReplayState struct {
	Valid      bool           `json:"valid"`
	ResetCount uint32         `json:"reset_count"`
	Offset     int64          `json:"offset"`  // bytes of the log verified so far
	Entries    int            `json:"entries"` // entries verified so far
	Read       uint64         `json:"read"`    // entries the last read held, for hints
	PCR10      []byte         `json:"pcr10"`   // PCR 10 after the verified entries
	BootPCRs   map[int][]byte `json:"boot_pcrs,omitempty"`
}

// QuoteResult is what a verified quote and log show.
type QuoteResult struct {
	Quote      *attest.QuoteInfo
	IMA        *ima.ReplayResult
	IMAEntries []ima.Entry // the newly attested part of the log
	PCRs       map[int][]byte
	// BootLog is the firmware event log, proven by replay to the quoted
	// PCRs 0-9; nil when the agent sent none (incremental quotes).
	// bootpolicy checks its content.
	BootLog    *eventlog.Log
	BootLogRaw []byte
	// BootChanged is set when a quote without the event log shows PCRs 0-9
	// that differ from the ones checked at the start of this boot.
	BootChanged bool
	// Next is the replay state after this quote.
	Next ReplayState

	AgentVersion string
	Canary       []byte // the canary asked for; nil if none
	CanaryStatus string // what the agent said about it
	Sweep        *protocol.SweepReport
	MountsAsked  bool
	Mounts       *protocol.MountAudit
}

// errNewBoot means the quote is from a new boot (another TPM resetCount),
// so the incremental state does not apply; the caller asks again for the
// whole log.
var errNewBoot = errors.New("quote: new boot, the whole log is needed")

// bootPCRs are the PCRs the firmware and boot loader extend; they do not
// change after boot.
const bootPCRs = 10

// CheckQuote verifies a quote from an enrolled node: AK signature, nonce,
// PCR values, and that the log sent from offset continues the verified
// replay in st (nil or invalid: from the start) to the quoted PCR 10.
func CheckQuote(e *Enrolled, nonce []byte, resp *protocol.QuoteResponse, st *ReplayState) (*QuoteResult, error) {
	if resp.Version != protocol.Version {
		return nil, fmt.Errorf("quote: version %q", resp.Version)
	}
	ak, err := attest.ParsePublic(e.AKPublic)
	if err != nil {
		return nil, err
	}
	pcrs := map[int][]byte{}
	for k, v := range resp.PCRs {
		i, err := strconv.Atoi(k)
		if err != nil || i < 0 || i > 23 {
			return nil, fmt.Errorf("quote: bad PCR index %q", k)
		}
		pcrs[i] = v
	}
	q, err := attest.VerifyQuote(ak, resp.Attest, resp.Signature, nonce, pcrs)
	if err != nil {
		return nil, err
	}
	pcr10, ok := pcrs[ima.PCR]
	if !ok {
		return nil, errors.New("quote: PCR 10 not quoted")
	}
	incremental := st != nil && st.Valid
	if incremental && q.ResetCount != st.ResetCount {
		return nil, errNewBoot
	}
	var offset int64
	start := make([]byte, 32)
	if incremental {
		offset, start = st.Offset, st.PCR10
	}
	if resp.IMAOffset != offset {
		return nil, fmt.Errorf("quote: IMA log sent from offset %d, asked for %d, in the same boot (the log cannot shrink)", resp.IMAOffset, offset)
	}
	entries, err := ima.ParseLog(resp.IMALog)
	if err != nil {
		return nil, err
	}
	r, err := ima.ReplayFrom(entries, start, pcr10)
	if err != nil {
		return nil, err
	}
	res := &QuoteResult{Quote: q, IMA: r, IMAEntries: entries[:r.MatchedPrefix], PCRs: pcrs,
		AgentVersion: resp.AgentVersion, CanaryStatus: resp.Canary, Sweep: resp.Sweep, Mounts: resp.Mounts}
	res.Next = ReplayState{Valid: true, ResetCount: q.ResetCount, Offset: offset + r.Bytes, PCR10: r.Final}
	if incremental {
		res.Next.Entries = st.Entries + r.MatchedPrefix
		res.Next.BootPCRs = st.BootPCRs
	} else {
		res.Next.Entries = r.MatchedPrefix
	}
	res.Next.Read = uint64(res.Next.Entries + r.After)
	switch {
	case len(resp.EventLog) > 0:
		l, err := eventlog.Parse(resp.EventLog)
		if err != nil {
			return nil, err
		}
		if err := l.CheckReplay(pcrs); err != nil {
			return nil, err
		}
		res.BootLog, res.BootLogRaw = l, resp.EventLog
		res.Next.BootPCRs = map[int][]byte{}
		for i := 0; i < bootPCRs; i++ {
			res.Next.BootPCRs[i] = pcrs[i]
		}
	case incremental && st.BootPCRs != nil:
		for i := 0; i < bootPCRs; i++ {
			if !bytes.Equal(pcrs[i], st.BootPCRs[i]) {
				res.BootChanged = true
			}
		}
	}
	return res, nil
}
