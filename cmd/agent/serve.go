package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nodetrust/internal/version"
	"nodetrust/pkg/agent"
)

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", ":9443", "address to listen on")
	caPath := fs.String("verifier-ca", "/etc/nodetrust/verifier-ca.pem", "CA that issues the verifier's client certificate")
	dev := fs.String("device", envOr("NODETRUST_TPM_DEVICE", agent.DefaultDevice), "TPM device")
	logPath := fs.String("ima-log", envOr("NODETRUST_IMA_LOG", defaultIMALog), "IMA binary log")
	evPath := fs.String("event-log", envOr("NODETRUST_EVENTLOG", defaultEventLog), `boot event log ("none" for none)`)
	countPath := fs.String("ima-count", envOr("NODETRUST_IMA_COUNT", defaultIMACount), `IMA runtime_measurements_count, for hints ("none" for none)`)
	iidPath := fs.String("instance-id-file", "/var/lib/cloud/data/instance-id", "instance ID written by cloud-init")
	if err := fs.Parse(args); err != nil {
		return err
	}
	logger := log.New(os.Stderr, "", 0) // journald adds time and unit

	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		return fmt.Errorf("verifier CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("verifier CA: no certificate in " + *caPath)
	}

	t, err := agent.Open(*dev)
	if err != nil {
		return err
	}
	defer t.Close()
	srv, err := agent.NewServer(t, agent.ServerConfig{IMALog: *logPath, IMACount: eventLogPath(*countPath),
		EventLog: eventLogPath(*evPath), InstanceIDFile: *iidPath, Version: version.String("agent"), Logger: logger})
	if err != nil {
		return err
	}
	hs := srv.HTTPServer(*listen, pool)
	spki := sha256.Sum256(srv.SPKI())
	logger.Printf("%s listening on %s; TLS key sha256 %x (new every start, bound into every quote)",
		version.String("agent"), *listen, spki[:8])

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServeTLS("", "") }()
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Printf("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
}
