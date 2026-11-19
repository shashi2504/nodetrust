package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nodetrust/internal/version"
	"nodetrust/pkg/bootpolicy"
	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/joinref"
	"nodetrust/pkg/manifest"
	"nodetrust/pkg/nodetrust"
	"nodetrust/pkg/provider/aws"
	"nodetrust/pkg/verifier"
)

// serveConfig is /etc/nodetrust/verifier/config.json.
type serveConfig struct {
	Region        string              `json:"region"` // empty: the instance's region
	Bucket        string              `json:"manifest_bucket"`
	AllowedAMIs   []string            `json:"allowed_amis"`
	WorkerFilters map[string][]string `json:"worker_filters"`
	AgentPort     int                 `json:"agent_port"`
	Interval      string              `json:"interval"`
	StateDir      string              `json:"state_dir"`
	ClientCert    string              `json:"client_cert"`
	ClientKey     string              `json:"client_key"`
	SigningKey    string              `json:"signing_key"`
	RekorKey      string              `json:"rekor_key"`
	RuntimePolicy string              `json:"runtime_policy"`
	BootPolicy    string              `json:"boot_policy"`
	JoinReference string              `json:"join_reference"` // infra/phase4/join-reference.sh
	// Kube is the API server the signed NodeTrust updates go to (step 4.7).
	Kube struct {
		Server     string `json:"server"`
		CA         string `json:"ca"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	} `json:"kube"`
	TrustKey string `json:"trust_signing_key"` // ECDSA key that signs NodeTrust updates
	// DisableProbes turns off challenge probes ("canary", "sweep",
	// "mounts"); all are on by default (blueprint 6.2).
	DisableProbes []string `json:"disable_probes,omitempty"`
}

func loadServeConfig(path string) (*serveConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c serveConfig
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case c.Bucket == "" || len(c.AllowedAMIs) == 0 || len(c.WorkerFilters) == 0:
		return nil, errors.New("config: manifest_bucket, allowed_amis and worker_filters are required")
	case c.ClientCert == "" || c.ClientKey == "" || c.SigningKey == "" || c.RekorKey == "":
		return nil, errors.New("config: client_cert, client_key, signing_key and rekor_key are required")
	case c.RuntimePolicy == "" || c.BootPolicy == "" || c.StateDir == "" || c.JoinReference == "":
		return nil, errors.New("config: runtime_policy, boot_policy, join_reference and state_dir are required")
	case c.Kube.Server == "" || c.Kube.CA == "" || c.Kube.ClientCert == "" || c.Kube.ClientKey == "" || c.TrustKey == "":
		return nil, errors.New("config: kube (server, ca, client_cert, client_key) and trust_signing_key are required")
	}
	if c.AgentPort == 0 {
		c.AgentPort = 9443
	}
	return &c, nil
}

// serve runs the verifier service (Phase 4, step 4.2).
func serve(args []string) (code int) {
	defer func() { // readFile panics with a failure for a missing file
		if r := recover(); r != nil {
			f, ok := r.(failure)
			if !ok {
				panic(r)
			}
			code = fail(f)
		}
	}()
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/nodetrust/verifier/config.json", "configuration file")
	once := fs.Bool("once", false, "run one round, print the status and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := log.New(os.Stderr, "", 0) // journald adds time and unit
	cfg, err := loadServeConfig(*cfgPath)
	if err != nil {
		return fail(err)
	}
	probes := verifier.AllProbes
	for _, p := range cfg.DisableProbes {
		switch p {
		case "canary":
			probes.Canary = false
		case "sweep":
			probes.Sweep = false
		case "mounts":
			probes.Mounts = false
		default:
			return fail(fmt.Errorf("config: unknown probe %q in disable_probes", p))
		}
	}
	iv := 60 * time.Second
	if cfg.Interval != "" {
		if iv, err = time.ParseDuration(cfg.Interval); err != nil || iv < 5*time.Second {
			return fail(fmt.Errorf("config: interval %q (at least 5s)", cfg.Interval))
		}
	}
	cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
	if err != nil {
		return fail(fmt.Errorf("client certificate: %w", err))
	}
	signing, err := manifest.ParsePublicKeyPEM(readFile(cfg.SigningKey))
	if err != nil {
		return fail(fmt.Errorf("signing key: %w", err))
	}
	rekor, err := manifest.ParsePublicKeyPEM(readFile(cfg.RekorKey))
	if err != nil {
		return fail(fmt.Errorf("rekor key: %w", err))
	}
	rt, err := imapolicy.LoadPolicy(readFile(cfg.RuntimePolicy))
	if err != nil {
		return fail(err)
	}
	jr, err := joinref.Load(cfg.JoinReference)
	if err != nil {
		return fail(err)
	}
	kube, err := nodetrust.NewKube(cfg.Kube.Server, readFile(cfg.Kube.CA), readFile(cfg.Kube.ClientCert), readFile(cfg.Kube.ClientKey))
	if err != nil {
		return fail(err)
	}
	tkey, err := nodetrust.ParsePrivateKey(readFile(cfg.TrustKey))
	if err != nil {
		return fail(fmt.Errorf("trust signing key: %w", err))
	}
	tkid, _ := nodetrust.KeyID(&tkey.PublicKey)
	bp, err := bootpolicy.LoadPolicy(readFile(cfg.BootPolicy))
	if err != nil {
		return fail(err)
	}
	allowed := map[string]bool{}
	for _, a := range cfg.AllowedAMIs {
		if _, ok := bp.AMIs[a]; !ok {
			return fail(fmt.Errorf("config: allowed AMI %s has no entry in the boot policy", a))
		}
		allowed[a] = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	c, err := aws.New(ctx, cfg.Region)
	if err != nil {
		return fail(err)
	}
	d := &verifier.Daemon{
		Inventory:     &aws.Inventory{C: c, Filters: cfg.WorkerFilters, AgentPort: cfg.AgentPort},
		Endorsement:   c,
		Manifests:     &aws.ManifestStore{C: c, Bucket: cfg.Bucket, Pins: manifest.Pins{Signing: signing, Rekor: rekor}},
		AllowedAMIs:   allowed,
		RuntimePolicy: rt,
		BootPolicy:    bp,
		JoinRef:       jr,
		Publisher:     &nodetrust.Publisher{Kube: kube, Key: tkey},
		Cert:          cert,
		StateDir:      cfg.StateDir,
		Interval:      iv,
		Probes:        probes,
		Log:           logger,
	}
	if err := d.Load(); err != nil {
		return fail(err)
	}
	logger.Printf("%s: region %s, %d allowed AMI(s), healthy nodes every %s, probes %+v, state in %s, NodeTrust to %s signed with key %s",
		version.String("verifier"), c.Region, len(allowed), iv, probes, cfg.StateDir, cfg.Kube.Server, tkid)
	if *once {
		if err := d.Round(ctx); err != nil {
			return fail(err)
		}
		for _, n := range d.Status() {
			fmt.Printf("%-20s %-12s %-9s %5g critical=%t unattested=%t %s\n",
				n.InstanceID, n.State, n.Tier, n.Score, n.Critical, n.Unattested, n.Reason)
		}
		return 0
	}
	if err := d.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fail(err)
	}
	logger.Print("stopped")
	return 0
}
