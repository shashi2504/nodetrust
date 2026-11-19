// Command controller is the trust controller (Phase 5). It runs on the
// control plane host with that host's IAM role, reads the verifier's signed
// NodeTrust objects and acts on them (pkg/controller):
//
//	controller serve [-config /etc/nodetrust/controller/config.json] [-once]
//	controller approve -instance i-...   (as root on the same host)
//	controller terminate -config C -instance i-... -yes
//
// approve lets containment of one instance go past the circuit breaker.
// terminate destroys a quarantined instance after its evidence snapshots
// exist; it is never done automatically (blueprint 8.3).
package main

import (
	"bytes"
	"context"
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
	"nodetrust/pkg/controller"
	"nodetrust/pkg/nodetrust"
	"nodetrust/pkg/provider"
	"nodetrust/pkg/provider/aws"
)

// Config is the controller's configuration file.
type Config struct {
	Region          string  `json:"region"` // empty: the instance's region
	DryRun          bool    `json:"dry_run"`
	Interval        string  `json:"interval"`         // default 5s
	MaxAge          string  `json:"max_age"`          // default 3m
	BreakerNodes    int     `json:"breaker_nodes"`    // default 2
	BreakerFraction float64 `json:"breaker_fraction"` // default 0.3
	BreakerWindow   string  `json:"breaker_window"`   // default 10m
	StateDir        string  `json:"state_dir"`
	TrustPublicKey  string  `json:"trust_public_key"` // PEM: the verifier's NodeTrust signing key
	Kube            struct {
		Server     string `json:"server"`
		CA         string `json:"ca"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	} `json:"kube"`
	QuarantineSG string `json:"quarantine_sg"`
	NACL         string `json:"nacl"`
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			os.Exit(serve(os.Args[2:]))
		case "approve":
			os.Exit(approve(os.Args[2:]))
		case "terminate":
			os.Exit(terminate(os.Args[2:]))
		}
	}
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("controller"))
		return
	}
	fmt.Fprintln(os.Stderr, "usage: controller serve|approve|terminate")
	os.Exit(2)
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "controller:", err)
	return 1
}

func duration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

func loadConfig(path string) (*Config, *controller.Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var cfg Config
	dec := json.NewDecoder(bytesReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, nil, fmt.Errorf("config %s: %w", path, err)
	}
	cc := controller.DefaultConfig
	cc.DryRun = cfg.DryRun
	if cfg.BreakerNodes > 0 {
		cc.BreakerNodes = cfg.BreakerNodes
	}
	if cfg.BreakerFraction > 0 {
		cc.BreakerFraction = cfg.BreakerFraction
	}
	if cc.MaxAge, err = duration(cfg.MaxAge, cc.MaxAge); err != nil {
		return nil, nil, err
	}
	if cc.BreakerWindow, err = duration(cfg.BreakerWindow, cc.BreakerWindow); err != nil {
		return nil, nil, err
	}
	if cfg.StateDir == "" {
		cfg.StateDir = "/var/lib/nodetrust-controller"
	}
	return &cfg, &cc, nil
}

func cloud(ctx context.Context, cfg *Config) (*aws.Containment, error) {
	c, err := aws.New(ctx, cfg.Region)
	if err != nil {
		return nil, err
	}
	if cfg.QuarantineSG == "" || cfg.NACL == "" {
		return nil, errors.New("config: quarantine_sg and nacl are required")
	}
	return &aws.Containment{C: c, QuarantineSG: cfg.QuarantineSG, NACL: cfg.NACL}, nil
}

func serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/nodetrust/controller/config.json", "configuration file")
	once := fs.Bool("once", false, "run one round and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logger := log.New(os.Stderr, "", 0) // journald adds time and unit
	cfg, cc, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(err)
	}
	iv, err := duration(cfg.Interval, 5*time.Second)
	if err != nil || iv < time.Second {
		return fail(fmt.Errorf("config: interval %q", cfg.Interval))
	}
	pubPEM, err := os.ReadFile(cfg.TrustPublicKey)
	if err != nil {
		return fail(err)
	}
	pub, err := nodetrust.ParsePublicKey(pubPEM)
	if err != nil {
		return fail(fmt.Errorf("trust public key: %w", err))
	}
	ca, err1 := os.ReadFile(cfg.Kube.CA)
	cert, err2 := os.ReadFile(cfg.Kube.ClientCert)
	key, err3 := os.ReadFile(cfg.Kube.ClientKey)
	if err := errors.Join(err1, err2, err3); err != nil {
		return fail(err)
	}
	kube, err := nodetrust.NewKube(cfg.Kube.Server, ca, cert, key)
	if err != nil {
		return fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	cl, err := cloud(ctx, cfg)
	if err != nil {
		return fail(err)
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return fail(err)
	}
	c := &controller.Controller{Kube: controller.KubeAPI{K: kube}, Cloud: cl, Pub: pub, Cfg: *cc, StateDir: cfg.StateDir,
		Logf: logger.Printf}
	if err := c.Load(); err != nil {
		return fail(err)
	}
	id, _ := nodetrust.KeyID(pub)
	mode := "LIVE"
	if cc.DryRun {
		mode = "dry-run (log only)"
	}
	logger.Printf("%s: %s, every %s, NodeTrust from %s pinned to key %s, quarantine %s + %s, breaker >%d nodes or >%.0f%% in %s",
		version.String("controller"), mode, iv, cfg.Kube.Server, id, cfg.QuarantineSG, cfg.NACL,
		cc.BreakerNodes, cc.BreakerFraction*100, cc.BreakerWindow)
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		if err := c.Reconcile(rctx); err != nil {
			logger.Printf("round: %v", err)
		}
		cancel()
		if *once {
			return 0
		}
		select {
		case <-ctx.Done():
			return 0
		case <-t.C:
		}
	}
}

func approve(args []string) int {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	dir := fs.String("state-dir", "/var/lib/nodetrust-controller", "the controller's state directory")
	id := fs.String("instance", "", "instance to contain past the circuit breaker")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" {
		return fail(errors.New("-instance is required"))
	}
	if err := controller.Approve(*dir, *id); err != nil {
		return fail(err)
	}
	fmt.Println("approved containment of", *id)
	return 0
}

func terminate(args []string) int {
	fs := flag.NewFlagSet("terminate", flag.ContinueOnError)
	cfgPath := fs.String("config", "/etc/nodetrust/controller/config.json", "configuration file")
	id := fs.String("instance", "", "quarantined instance to terminate")
	yes := fs.Bool("yes", false, "confirm: the instance and its memory are destroyed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *id == "" || !*yes {
		return fail(errors.New("-instance and -yes are required"))
	}
	cfg, _, err := loadConfig(*cfgPath)
	if err != nil {
		return fail(err)
	}
	ctx := context.Background()
	cl, err := cloud(ctx, cfg)
	if err != nil {
		return fail(err)
	}
	st, err := cl.State(ctx, provider.InstanceID(*id))
	if err != nil {
		return fail(err)
	}
	if !st.Isolated || !st.Replaced {
		return fail(fmt.Errorf("%s is not quarantined and replaced yet (%+v)", *id, st))
	}
	if err := cl.Terminate(ctx, provider.InstanceID(*id)); err != nil {
		return fail(err)
	}
	fmt.Printf("terminated %s (evidence snapshots kept: %v)\n", *id, st.Snapshots)
	return 0
}

func bytesReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }
