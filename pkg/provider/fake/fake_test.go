package fake_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"

	"nodetrust/pkg/provider"
	"nodetrust/pkg/provider/conformance"
	"nodetrust/pkg/provider/fake"
)

func TestEndorsementConformance(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := fake.NewEndorsement()
	p.SetEK("i-0000000000000001", provider.EKECCP384, &key.PublicKey)

	conformance.RunEndorsement(t, conformance.EndorsementEnv{
		Provider: p,
		Instance: "i-0000000000000001",
		KeyType:  provider.EKECCP384,
		Want:     &key.PublicKey,
		Unknown:  "i-ffffffffffffffff",
	})
}

func TestContainmentConformance(t *testing.T) {
	p := fake.NewContainment()
	var n atomic.Int64
	conformance.RunContainment(t, conformance.ContainmentEnv{
		Provider: p,
		NewInstance: func(t *testing.T) provider.InstanceID {
			id := provider.InstanceID(fmt.Sprintf("i-%016x", n.Add(1)))
			p.AddInstance(id)
			return id
		},
		Unknown: "i-ffffffffffffffff",
	})
}

func TestContainmentRecordsCallsInOrder(t *testing.T) {
	ctx := context.Background()
	p := fake.NewContainment()
	p.AddInstance("i-1")

	if err := p.Isolate(ctx, "i-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Snapshot(ctx, "i-1", "test"); err != nil {
		t.Fatal(err)
	}
	if err := p.Replace(ctx, "i-1"); err != nil {
		t.Fatal(err)
	}

	got := p.Calls()
	want := []fake.Call{{"Isolate", "i-1"}, {"Snapshot", "i-1"}, {"Replace", "i-1"}}
	if len(got) != len(want) {
		t.Fatalf("got %d calls %v, want %v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("call %d: got %v, want %v", i, got[i], want[i])
		}
	}
}
