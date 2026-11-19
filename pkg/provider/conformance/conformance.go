// Package conformance holds the test suites every provider implementation
// must pass. The fake providers run them in unit tests; the AWS providers run
// them in integration tests against real instances (build tag aws_integration).
package conformance

import (
	"context"
	"crypto"
	"errors"
	"slices"
	"testing"
	"time"

	"nodetrust/pkg/provider"
)

// EndorsementEnv describes one test instance for RunEndorsement.
type EndorsementEnv struct {
	Provider provider.EndorsementProvider
	// Instance is an existing instance with a TPM.
	Instance provider.InstanceID
	// KeyType is a key type the platform offers for Instance.
	KeyType provider.EKKeyType
	// Want is the EK public key read directly from Instance's TPM, out of
	// band (for example with tpm2-tools), used to check the provider's answer.
	Want crypto.PublicKey
	// Unknown is an instance ID that does not exist.
	Unknown provider.InstanceID
}

// RunEndorsement checks the EndorsementProvider contract.
func RunEndorsement(t *testing.T, env EndorsementEnv) {
	t.Helper()

	t.Run("returns the TPM's EK", func(t *testing.T) {
		got, err := env.Provider.EKPublic(ctxFor(t), env.Instance, env.KeyType)
		if err != nil {
			t.Fatalf("EKPublic: %v", err)
		}
		eq, ok := got.(interface{ Equal(crypto.PublicKey) bool })
		if !ok {
			t.Fatalf("EKPublic returned %T, which has no Equal method", got)
		}
		if !eq.Equal(env.Want) {
			t.Fatal("EKPublic returned a key that differs from the one read from the TPM")
		}
	})

	t.Run("unknown instance", func(t *testing.T) {
		_, err := env.Provider.EKPublic(ctxFor(t), env.Unknown, env.KeyType)
		if !errors.Is(err, provider.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("unsupported key type", func(t *testing.T) {
		_, err := env.Provider.EKPublic(ctxFor(t), env.Instance, provider.EKKeyType("dsa-1024"))
		if !errors.Is(err, provider.ErrUnsupported) {
			t.Fatalf("want ErrUnsupported, got %v", err)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		pub, err := env.Provider.EKPublic(ctx, env.Instance, env.KeyType)
		if err == nil || pub != nil {
			t.Fatalf("want an error and no key, got key=%v err=%v", pub, err)
		}
	})
}

// ContainmentEnv describes how to get test instances for RunContainment.
type ContainmentEnv struct {
	Provider provider.ContainmentProvider
	// NewInstance returns a fresh, healthy instance that the suite may
	// isolate, snapshot, replace and terminate.
	NewInstance func(t *testing.T) provider.InstanceID
	// Unknown is an instance ID that does not exist.
	Unknown provider.InstanceID
}

// RunContainment checks the ContainmentProvider contract.
func RunContainment(t *testing.T, env ContainmentEnv) {
	t.Helper()
	p := env.Provider

	t.Run("full sequence is idempotent", func(t *testing.T) {
		ctx := ctxFor(t)
		id := env.NewInstance(t)

		for i := 0; i < 2; i++ {
			if err := p.Isolate(ctx, id); err != nil {
				t.Fatalf("Isolate call %d: %v", i+1, err)
			}
		}
		first, err := p.Snapshot(ctx, id, "conformance")
		if err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		if len(first) == 0 {
			t.Fatal("Snapshot returned no snapshot IDs")
		}
		second, err := p.Snapshot(ctx, id, "conformance")
		if err != nil {
			t.Fatalf("second Snapshot: %v", err)
		}
		if !slices.Equal(first, second) {
			t.Fatalf("Snapshot is not idempotent: %v then %v", first, second)
		}
		for i := 0; i < 2; i++ {
			if err := p.Replace(ctx, id); err != nil {
				t.Fatalf("Replace call %d: %v", i+1, err)
			}
		}
		st := mustState(t, p, id)
		if !st.Isolated || !st.Replaced || st.Terminated || !slices.Equal(st.Snapshots, first) {
			t.Fatalf("unexpected state before terminate: %+v", st)
		}
		for i := 0; i < 2; i++ {
			if err := p.Terminate(ctx, id); err != nil {
				t.Fatalf("Terminate call %d: %v", i+1, err)
			}
		}
		if st := mustState(t, p, id); !st.Terminated {
			t.Fatalf("instance not terminated: %+v", st)
		}
	})

	t.Run("replace before isolate is refused", func(t *testing.T) {
		id := env.NewInstance(t)
		if err := p.Replace(ctxFor(t), id); !errors.Is(err, provider.ErrPrecondition) {
			t.Fatalf("want ErrPrecondition, got %v", err)
		}
		if st := mustState(t, p, id); st.Replaced {
			t.Fatal("refused Replace still marked the instance replaced")
		}
	})

	t.Run("terminate before snapshot is refused", func(t *testing.T) {
		ctx := ctxFor(t)
		id := env.NewInstance(t)
		if err := p.Isolate(ctx, id); err != nil {
			t.Fatalf("Isolate: %v", err)
		}
		if err := p.Terminate(ctx, id); !errors.Is(err, provider.ErrPrecondition) {
			t.Fatalf("want ErrPrecondition, got %v", err)
		}
		if st := mustState(t, p, id); st.Terminated {
			t.Fatal("refused Terminate still marked the instance terminated")
		}
	})

	t.Run("steps after terminate are refused", func(t *testing.T) {
		ctx := ctxFor(t)
		id := env.NewInstance(t)
		if err := p.Isolate(ctx, id); err != nil {
			t.Fatalf("Isolate: %v", err)
		}
		if _, err := p.Snapshot(ctx, id, "conformance"); err != nil {
			t.Fatalf("Snapshot: %v", err)
		}
		if err := p.Terminate(ctx, id); err != nil {
			t.Fatalf("Terminate: %v", err)
		}
		if err := p.Isolate(ctx, id); !errors.Is(err, provider.ErrPrecondition) {
			t.Errorf("Isolate after terminate: want ErrPrecondition, got %v", err)
		}
		if _, err := p.Snapshot(ctx, id, "conformance"); !errors.Is(err, provider.ErrPrecondition) {
			t.Errorf("Snapshot after terminate: want ErrPrecondition, got %v", err)
		}
		if err := p.Replace(ctx, id); !errors.Is(err, provider.ErrPrecondition) {
			t.Errorf("Replace after terminate: want ErrPrecondition, got %v", err)
		}
	})

	t.Run("unknown instance", func(t *testing.T) {
		ctx := ctxFor(t)
		u := env.Unknown
		if err := p.Isolate(ctx, u); !errors.Is(err, provider.ErrNotFound) {
			t.Errorf("Isolate: want ErrNotFound, got %v", err)
		}
		if _, err := p.Snapshot(ctx, u, "conformance"); !errors.Is(err, provider.ErrNotFound) {
			t.Errorf("Snapshot: want ErrNotFound, got %v", err)
		}
		if err := p.Replace(ctx, u); !errors.Is(err, provider.ErrNotFound) {
			t.Errorf("Replace: want ErrNotFound, got %v", err)
		}
		if err := p.Terminate(ctx, u); !errors.Is(err, provider.ErrNotFound) {
			t.Errorf("Terminate: want ErrNotFound, got %v", err)
		}
		if _, err := p.State(ctx, u); !errors.Is(err, provider.ErrNotFound) {
			t.Errorf("State: want ErrNotFound, got %v", err)
		}
	})

	t.Run("cancelled context changes nothing", func(t *testing.T) {
		id := env.NewInstance(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := p.Isolate(ctx, id); err == nil {
			t.Fatal("Isolate with a cancelled context returned nil")
		}
		if st := mustState(t, p, id); st.Isolated {
			t.Fatal("Isolate with a cancelled context still isolated the instance")
		}
	})
}

func mustState(t *testing.T, p provider.ContainmentProvider, id provider.InstanceID) provider.State {
	t.Helper()
	st, err := p.State(ctxFor(t), id)
	if err != nil {
		t.Fatalf("State(%s): %v", id, err)
	}
	return st
}

// ctxFor returns a context that ends with the test, with a generous timeout
// so real cloud calls in integration runs can finish.
func ctxFor(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(cancel)
	return ctx
}
