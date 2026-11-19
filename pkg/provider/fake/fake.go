// Package fake provides in-memory provider implementations for unit tests of
// the verifier and controller. They follow the same contract as the real
// providers and are checked by the same conformance suites.
package fake

import (
	"context"
	"crypto"
	"fmt"
	"slices"
	"sync"

	"nodetrust/pkg/provider"
)

// Endorsement is an in-memory EndorsementProvider.
type Endorsement struct {
	mu   sync.Mutex
	keys map[provider.InstanceID]map[provider.EKKeyType]crypto.PublicKey
}

// NewEndorsement returns an empty Endorsement provider.
func NewEndorsement() *Endorsement {
	return &Endorsement{keys: map[provider.InstanceID]map[provider.EKKeyType]crypto.PublicKey{}}
}

// SetEK registers the EK of one instance for one key type.
func (e *Endorsement) SetEK(id provider.InstanceID, kt provider.EKKeyType, pub crypto.PublicKey) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.keys[id] == nil {
		e.keys[id] = map[provider.EKKeyType]crypto.PublicKey{}
	}
	e.keys[id][kt] = pub
}

// EKPublic implements provider.EndorsementProvider.
func (e *Endorsement) EKPublic(ctx context.Context, id provider.InstanceID, kt provider.EKKeyType) (crypto.PublicKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if kt != provider.EKRSA2048 && kt != provider.EKECCP384 {
		return nil, fmt.Errorf("key type %q: %w", kt, provider.ErrUnsupported)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	byType, ok := e.keys[id]
	if !ok {
		return nil, fmt.Errorf("instance %s: %w", id, provider.ErrNotFound)
	}
	pub, ok := byType[kt]
	if !ok {
		return nil, fmt.Errorf("instance %s key type %q: %w", id, kt, provider.ErrUnsupported)
	}
	return pub, nil
}

// Call records one containment call, for assertions in controller tests.
type Call struct {
	Method string
	ID     provider.InstanceID
}

// Containment is an in-memory ContainmentProvider.
type Containment struct {
	mu        sync.Mutex
	instances map[provider.InstanceID]*provider.State
	nextSnap  int
	calls     []Call
}

// NewContainment returns an empty Containment provider.
func NewContainment() *Containment {
	return &Containment{instances: map[provider.InstanceID]*provider.State{}}
}

// AddInstance registers a healthy, running instance.
func (c *Containment) AddInstance(id provider.InstanceID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.instances[id] = &provider.State{}
}

// Calls returns a copy of every call made so far, in order.
func (c *Containment) Calls() []Call {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.calls)
}

// begin checks the context, records the call and returns the instance state.
// The caller must hold c.mu.
func (c *Containment) begin(ctx context.Context, method string, id provider.InstanceID) (*provider.State, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.calls = append(c.calls, Call{Method: method, ID: id})
	st, ok := c.instances[id]
	if !ok {
		return nil, fmt.Errorf("instance %s: %w", id, provider.ErrNotFound)
	}
	return st, nil
}

// Isolate implements provider.ContainmentProvider.
func (c *Containment) Isolate(ctx context.Context, id provider.InstanceID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.begin(ctx, "Isolate", id)
	if err != nil {
		return err
	}
	if st.Terminated {
		return fmt.Errorf("isolate %s after terminate: %w", id, provider.ErrPrecondition)
	}
	st.Isolated = true
	return nil
}

// Snapshot implements provider.ContainmentProvider.
func (c *Containment) Snapshot(ctx context.Context, id provider.InstanceID, reason string) ([]provider.SnapshotID, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.begin(ctx, "Snapshot", id)
	if err != nil {
		return nil, err
	}
	if st.Terminated {
		return nil, fmt.Errorf("snapshot %s after terminate: %w", id, provider.ErrPrecondition)
	}
	if len(st.Snapshots) == 0 {
		c.nextSnap++
		st.Snapshots = []provider.SnapshotID{provider.SnapshotID(fmt.Sprintf("snap-fake-%04d", c.nextSnap))}
	}
	return slices.Clone(st.Snapshots), nil
}

// Replace implements provider.ContainmentProvider.
func (c *Containment) Replace(ctx context.Context, id provider.InstanceID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.begin(ctx, "Replace", id)
	if err != nil {
		return err
	}
	if st.Terminated {
		return fmt.Errorf("replace %s after terminate: %w", id, provider.ErrPrecondition)
	}
	if !st.Isolated {
		return fmt.Errorf("replace %s before isolate: %w", id, provider.ErrPrecondition)
	}
	st.Replaced = true
	return nil
}

// Terminate implements provider.ContainmentProvider.
func (c *Containment) Terminate(ctx context.Context, id provider.InstanceID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	st, err := c.begin(ctx, "Terminate", id)
	if err != nil {
		return err
	}
	if len(st.Snapshots) == 0 {
		return fmt.Errorf("terminate %s before snapshot: %w", id, provider.ErrPrecondition)
	}
	st.Terminated = true
	return nil
}

// State implements provider.ContainmentProvider.
func (c *Containment) State(ctx context.Context, id provider.InstanceID) (provider.State, error) {
	if err := ctx.Err(); err != nil {
		return provider.State{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.instances[id]
	if !ok {
		return provider.State{}, fmt.Errorf("instance %s: %w", id, provider.ErrNotFound)
	}
	out := *st
	out.Snapshots = slices.Clone(st.Snapshots)
	return out, nil
}

// Compile-time interface checks.
var (
	_ provider.EndorsementProvider = (*Endorsement)(nil)
	_ provider.ContainmentProvider = (*Containment)(nil)
)
