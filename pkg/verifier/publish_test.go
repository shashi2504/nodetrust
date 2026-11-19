package verifier

import (
	"context"
	"sync"
	"testing"
	"time"

	"nodetrust/pkg/imapolicy"
	"nodetrust/pkg/nodetrust"
	"nodetrust/pkg/trust"
)

type fakePublisher struct {
	mu      sync.Mutex
	states  []*nodetrust.State
	removed []string
}

func (f *fakePublisher) Publish(_ context.Context, st *nodetrust.State) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.states = append(f.states, st)
	return nil
}

func (f *fakePublisher) Remove(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, id)
	return nil
}

func TestPublishEachCycle(t *testing.T) {
	dir := t.TempDir()
	p := &fakePublisher{}
	newD := func() *Daemon {
		d := &Daemon{StateDir: dir, RuntimePolicy: &imapolicy.Policy{}, Publisher: p}
		if err := d.Load(); err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := newD()
	w := Worker{InstanceID: "i-1", Addr: "10.42.17.24:9443", AMI: "ami-g"}
	cycle := func(d *Daemon, n int, items ...imapolicy.Item) {
		d.observe(&outcome{w: w, obs: []Observation{{At: t0.Add(time.Duration(n) * time.Minute), State: StateVerified,
			Quote: q(1, 0, uint64(n)), Verdict: verdict(items...)}}})
	}
	cycle(d, 1)
	cycle(d, 2, it("/usr/bin/ls", imapolicy.Mismatch))
	// A verifier restart keeps counting from where it was.
	d = newD()
	cycle(d, 3)
	if len(p.states) != 3 {
		t.Fatalf("%d updates", len(p.states))
	}
	for i, st := range p.states {
		if st.Seq != uint64(i+1) || st.InstanceID != "i-1" || st.AMI != "ami-g" || st.State != StateVerified {
			t.Fatalf("update %d: %+v", i, st)
		}
	}
	if s := p.states[2]; s.Tier != trust.Warning || s.Score != 90 || len(s.Files) != 1 || s.LastAttestation.IsZero() {
		t.Fatalf("last update: %+v", s)
	}
	if n := d.Status()[0]; n.Published != 3 || n.PublishError != "" {
		t.Fatalf("status: %+v", n)
	}
	// The instance leaves the inventory: its object is removed.
	d.forget(map[string]bool{})
	time.Sleep(100 * time.Millisecond)
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.removed) != 1 || p.removed[0] != "i-1" {
		t.Fatalf("removed %v", p.removed)
	}
}
