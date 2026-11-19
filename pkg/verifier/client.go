package verifier

// Client for the agent's mTLS service (blueprint Phase 3, step 3.3).

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"nodetrust/pkg/protocol"
)

// Client talks to one agent.
type Client struct {
	addr string
	http *http.Client
}

// NewClient makes a client that presents cert (issued by the verifier CA).
// The agent's certificate is not checked against any CA: it is a fresh key
// per agent start, and what makes it trustworthy is that the TPM signs it
// into every quote (protocol.BindNonce). Enrollment needs no channel trust,
// because only the TPM can produce the secret.
func NewClient(addr string, cert tls.Certificate) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			Certificates:       []tls.Certificate{cert},
			InsecureSkipVerify: true, //nolint:gosec // trust comes from the quote binding, see above
		},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxConnsPerHost:     1,
	}
	return &Client{addr: addr, http: &http.Client{Transport: tr, Timeout: 90 * time.Second}}
}

// post sends a message and decodes the reply. It returns the agent's TLS
// public key (DER SubjectPublicKeyInfo) as seen on this connection.
func (c *Client) post(ctx context.Context, path string, in, out any) ([]byte, error) {
	var body io.Reader = http.NoBody
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+c.addr+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: agent answered %d: %s", path, resp.StatusCode, bytes.TrimSpace(raw))
	}
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no TLS peer certificate")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return resp.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo, nil
}

// Enroll runs the credential activation with the agent. instanceID and
// cloudEK come from the cloud provider, never from the agent.
func (c *Client) Enroll(ctx context.Context, instanceID string, cloudEK crypto.PublicKey) (*Enrolled, error) {
	var req protocol.EnrollRequest
	if _, err := c.post(ctx, "/v1/enroll", nil, &req); err != nil {
		return nil, err
	}
	ch, pending, err := NewChallenge(instanceID, cloudEK, &req)
	if err != nil {
		return nil, err
	}
	var resp protocol.ChallengeResponse
	if _, err := c.post(ctx, "/v1/activate", ch, &resp); err != nil {
		return nil, err
	}
	return Finish(pending, &resp, time.Now())
}

// QuoteOptions say what to ask for in a challenge.
type QuoteOptions struct {
	State   ReplayState // where the verifier's replay stands; invalid asks for the whole log and the event log
	Canary  bool
	Sweep   []string
	SweepMS int
	Mounts  bool
}

// Quote runs one challenge and checks the answer, including the binding to
// the TLS key seen on the connection that carried it. If the node rebooted
// since the replay state was saved, it asks again for the whole log.
func (c *Client) Quote(ctx context.Context, e *Enrolled, o QuoteOptions) (*QuoteResult, error) {
	r, err := c.quote(ctx, e, o)
	if errors.Is(err, errNewBoot) {
		o.State = ReplayState{}
		r, err = c.quote(ctx, e, o)
	}
	return r, err
}

func (c *Client) quote(ctx context.Context, e *Enrolled, o QuoteOptions) (*QuoteResult, error) {
	nonce := make([]byte, protocol.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	req := &protocol.QuoteRequest{Version: protocol.Version, Nonce: nonce, Sweep: o.Sweep, SweepMS: o.SweepMS, Mounts: o.Mounts}
	if o.State.Valid {
		req.IMAOffset = o.State.Offset
	} else {
		req.EventLog = true
	}
	if o.Canary {
		req.Canary = make([]byte, protocol.CanarySize)
		if _, err := rand.Read(req.Canary); err != nil {
			return nil, err
		}
	}
	var resp protocol.QuoteResponse
	spki, err := c.post(ctx, "/v1/quote", req, &resp)
	if err != nil {
		return nil, err
	}
	r, err := CheckQuote(e, protocol.BindNonce(nonce, spki), &resp, &o.State)
	if errors.Is(err, errNewBoot) {
		return nil, err
	}
	if err != nil {
		return nil, &EvidenceError{fmt.Errorf("quote over TLS: %w", err)}
	}
	r.Canary, r.MountsAsked = req.Canary, o.Mounts
	return r, nil
}

// Hint waits (about 25 s) until the node's IMA log has more than count
// entries, and returns the current count.
func (c *Client) Hint(ctx context.Context, count uint64) (uint64, error) {
	var resp protocol.HintResponse
	if _, err := c.post(ctx, "/v1/hint", &protocol.HintRequest{Version: protocol.Version, Count: count}, &resp); err != nil {
		return 0, err
	}
	return resp.Count, nil
}

// EvidenceError is a quote the agent sent that does not verify (signature,
// nonce binding, PCR digest, log replay), as opposed to an agent that could
// not be reached. The first is evidence against the node; the second is not.
type EvidenceError struct{ Err error }

func (e *EvidenceError) Error() string { return e.Err.Error() }
func (e *EvidenceError) Unwrap() error { return e.Err }
