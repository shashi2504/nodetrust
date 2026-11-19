package agent

// The agent's network service (blueprint Phase 3, step 3.3): HTTPS with
// mutual TLS on port 9443, three POST endpoints carrying the pkg/protocol
// messages. The agent decides nothing; it only answers.
//
// Client side: only certificates issued by the verifier CA, for the client
// "nodetrust-verifier", are accepted (pods on the node can reach the node's
// address, so the security group alone is not enough).
//
// Server side: the TLS key is made fresh at every start and never stored.
// The verifier does not trust it by itself; instead every quote signs
// protocol.BindNonce(nonce, this key), which ties the TPM to this TLS session.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"nodetrust/pkg/protocol"
)

// VerifierClientName is the common name the verifier's client certificate must carry.
const VerifierClientName = "nodetrust-verifier"

// ServerConfig configures the agent service.
type ServerConfig struct {
	IMALog         string // path of the binary IMA log
	IMACount       string // path of runtime_measurements_count (hints); empty disables hints
	EventLog       string // path of the boot event log; empty for none (simulator)
	InstanceIDFile string // where cloud-init stores the instance ID
	CanaryPath     string // where the canary is written; empty means protocol.CanaryPath
	Proc           string // procfs for the mount audit; empty means /proc
	Version        string // agent version, reported in every quote
	Logger         *log.Logger
}

// Server is the agent's HTTPS service around one open TPM.
type Server struct {
	mu   sync.Mutex // the TPM handles one command sequence at a time
	tpm  *TPM
	cfg  ServerConfig
	cert tls.Certificate
	spki []byte
}

// NewServer makes the ephemeral TLS identity.
func NewServer(t *TPM, cfg ServerConfig) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = log.New(os.Stderr, "nodetrust-agent: ", log.LstdFlags)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "nodetrust-agent"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	leaf, _ := x509.ParseCertificate(der)
	return &Server{
		tpm:  t,
		cfg:  cfg,
		cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k, Leaf: leaf},
		spki: leaf.RawSubjectPublicKeyInfo,
	}, nil
}

// SPKI is the DER SubjectPublicKeyInfo of the agent's TLS key.
func (s *Server) SPKI() []byte { return s.spki }

// TLSConfig requires TLS 1.3 and a client certificate from verifierCAs.
func (s *Server) TLSConfig(verifierCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{s.cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    verifierCAs,
		VerifyPeerCertificate: func(_ [][]byte, chains [][]*x509.Certificate) error {
			if len(chains) == 0 || chains[0][0].Subject.CommonName != VerifierClientName {
				return errors.New("client certificate is not for " + VerifierClientName)
			}
			return nil
		},
	}
}

// HTTPServer returns the http.Server with timeouts and body limits.
func (s *Server) HTTPServer(addr string, verifierCAs *x509.CertPool) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enroll", s.handle(s.enroll))
	mux.HandleFunc("POST /v1/activate", s.handle(s.activate))
	mux.HandleFunc("POST /v1/quote", s.handle(s.quote))
	mux.HandleFunc("POST /v1/hint", s.hint) // no TPM: does not take the lock
	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		TLSConfig:         s.TLSConfig(verifierCAs),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          s.cfg.Logger,
	}
}

type handlerFunc func(body []byte) (any, error)

func (s *Server) handle(f handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
		if err != nil {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		s.mu.Lock()
		out, err := f(body)
		s.mu.Unlock()
		if err != nil {
			s.cfg.Logger.Printf("%s from %s: %v", r.URL.Path, r.RemoteAddr, err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

func decode(body []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) enroll([]byte) (any, error) {
	iid, _ := os.ReadFile(s.cfg.InstanceIDFile)
	return &protocol.EnrollRequest{
		Version:    protocol.Version,
		InstanceID: strings.TrimSpace(string(iid)),
		EKPublic:   s.tpm.EK.Public,
		AKPublic:   s.tpm.AK.Public,
	}, nil
}

func (s *Server) activate(body []byte) (any, error) {
	var ch protocol.Challenge
	if err := decode(body, &ch); err != nil {
		return nil, fmt.Errorf("challenge: %w", err)
	}
	if ch.Version != protocol.Version {
		return nil, fmt.Errorf("challenge version %q", ch.Version)
	}
	secret, err := s.tpm.ActivateCredential(ch.IDObject, ch.EncryptedSecret)
	if err != nil {
		return nil, err
	}
	return &protocol.ChallengeResponse{Version: protocol.Version, Secret: secret}, nil
}

// Limits on what a quote request may ask for.
const (
	maxSweepPaths = 64
	maxSweepTime  = 25 * time.Second
)

func (s *Server) quote(body []byte) (any, error) {
	var req protocol.QuoteRequest
	if err := decode(body, &req); err != nil {
		return nil, fmt.Errorf("quote request: %w", err)
	}
	if req.Version != protocol.Version || len(req.Nonce) != protocol.NonceSize {
		return nil, fmt.Errorf("quote request: want version %q and a %d-byte nonce", protocol.Version, protocol.NonceSize)
	}
	if len(req.Canary) != 0 && len(req.Canary) != protocol.CanarySize || len(req.Sweep) > maxSweepPaths || req.IMAOffset < 0 {
		return nil, errors.New("quote request: bad canary, sweep or offset")
	}
	resp := &protocol.QuoteResponse{Version: protocol.Version, AgentVersion: s.cfg.Version, PCRs: map[string][]byte{}}

	// Everything that should be measured goes before the quote.
	if len(req.Canary) > 0 {
		p := s.cfg.CanaryPath
		if p == "" {
			p = protocol.CanaryPath
		}
		resp.Canary = WriteCanary(p, req.Canary)
	}
	if len(req.Sweep) > 0 {
		budget := time.Duration(req.SweepMS) * time.Millisecond
		if budget <= 0 || budget > maxSweepTime {
			budget = maxSweepTime
		}
		resp.Sweep = Sweep(req.Sweep, budget)
	}
	if req.Mounts {
		proc := s.cfg.Proc
		if proc == "" {
			proc = "/proc"
		}
		resp.Mounts = AuditMounts(proc)
	}

	q, err := s.tpm.Quote(protocol.BindNonce(req.Nonce, s.spki))
	if err != nil {
		return nil, err
	}
	// Read the log after the quote, so it holds every entry the quote covers.
	logBytes, err := os.ReadFile(s.cfg.IMALog)
	if err != nil {
		return nil, fmt.Errorf("read IMA log: %w", err)
	}
	if req.IMAOffset <= int64(len(logBytes)) {
		resp.IMAOffset, resp.IMALog = req.IMAOffset, logBytes[req.IMAOffset:]
	} else { // the log is shorter: a new boot
		resp.IMAOffset, resp.IMALog = 0, logBytes
	}
	resp.Attest, resp.Signature = q.Attest, q.Signature
	if req.EventLog && s.cfg.EventLog != "" {
		if resp.EventLog, err = os.ReadFile(s.cfg.EventLog); err != nil {
			return nil, fmt.Errorf("read boot event log: %w", err)
		}
	}
	for i, v := range q.PCRs {
		resp.PCRs[strconv.Itoa(i)] = v
	}
	return resp, nil
}

// hintWait is how long a hint request waits for new measurements.
const hintWait = 25 * time.Second

// hint answers once the IMA log has more entries than the verifier last
// saw, or after hintWait.
func (s *Server) hint(w http.ResponseWriter, r *http.Request) {
	var req protocol.HintRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err == nil {
		err = decode(body, &req)
	}
	if err != nil || req.Version != protocol.Version || s.cfg.IMACount == "" {
		http.Error(w, "bad hint request", http.StatusBadRequest)
		return
	}
	deadline := time.Now().Add(hintWait)
	var n uint64
	for {
		if n, err = MeasurementCount(s.cfg.IMACount); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if n > req.Count || time.Now().After(deadline) {
			break
		}
		select {
		case <-r.Context().Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(&protocol.HintResponse{Version: protocol.Version, Count: n})
}
