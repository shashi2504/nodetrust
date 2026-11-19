package aws

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"nodetrust/pkg/manifest"
	"nodetrust/pkg/verifier"
)

// Inventory lists running workers with DescribeInstances (verifier.Inventory).
type Inventory struct {
	C         *Client
	Filters   map[string][]string // e.g. tag:role=worker, tag:project=nodetrust
	AgentPort int
}

// Workers implements verifier.Inventory.
func (in *Inventory) Workers(ctx context.Context) ([]verifier.Worker, error) {
	f := map[string][]string{"instance-state-name": {"running"}}
	for k, v := range in.Filters {
		f[k] = v
	}
	is, err := in.C.DescribeInstances(ctx, f)
	if err != nil {
		return nil, err
	}
	var out []verifier.Worker
	for _, i := range is {
		if i.PrivateIP == "" {
			continue
		}
		out = append(out, verifier.Worker{
			InstanceID:   i.ID,
			Addr:         net.JoinHostPort(i.PrivateIP, strconv.Itoa(in.AgentPort)),
			AMI:          i.ImageID,
			RootVolumeID: i.RootVolumeID,
			Zone:         i.Zone,
		})
	}
	return out, nil
}

// ManifestStore reads an AMI's signed bundle from the manifest bucket and
// verifies it (verifier.ManifestSource). A verified manifest is kept for the
// life of the process (AMIs and their manifests do not change); a failure is
// retried after RetryAfter.
type ManifestStore struct {
	C          *Client
	Bucket     string
	Pins       manifest.Pins
	RetryAfter time.Duration
	// Verify defaults to manifest.VerifyBundle.
	Verify func(b *manifest.Bundle, ami string, pins manifest.Pins) (*manifest.Trusted, error)

	mu     sync.Mutex
	ok     map[string]*manifest.Trusted
	failed map[string]failure
}

type failure struct {
	err error
	at  time.Time
}

// Object size limits: the manifest of an Ubuntu worker is about 4 MB gzipped.
const (
	maxManifest = 256 << 20
	maxSmall    = 1 << 20
)

// Trusted implements verifier.ManifestSource.
func (m *ManifestStore) Trusted(ctx context.Context, ami string) (*manifest.Trusted, error) {
	m.mu.Lock()
	if m.ok == nil {
		m.ok, m.failed = map[string]*manifest.Trusted{}, map[string]failure{}
	}
	if t := m.ok[ami]; t != nil {
		m.mu.Unlock()
		return t, nil
	}
	retry := m.RetryAfter
	if retry == 0 {
		retry = 5 * time.Minute
	}
	if f, ok := m.failed[ami]; ok && time.Since(f.at) < retry {
		m.mu.Unlock()
		return nil, f.err
	}
	m.mu.Unlock()

	t, err := m.fetch(ctx, ami)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.failed[ami] = failure{err, time.Now()}
		return nil, err
	}
	delete(m.failed, ami)
	m.ok[ami] = t
	return t, nil
}

func (m *ManifestStore) fetch(ctx context.Context, ami string) (*manifest.Trusted, error) {
	var b manifest.Bundle
	for _, o := range []struct {
		key string
		max int64
		dst *[]byte
	}{
		{"signed/" + ami + "/statement.json", maxSmall, &b.Statement},
		{"signed/" + ami + "/statement.sig", maxSmall, &b.Signature},
		{"signed/" + ami + "/rekor-entry.json", maxSmall, &b.RekorEntry},
		{"manifests/" + ami + "/manifest.json.gz", maxManifest, &b.Manifest},
	} {
		v, err := m.C.GetObject(ctx, m.Bucket, o.key, o.max)
		if err != nil {
			return nil, fmt.Errorf("s3://%s/%s: %w", m.Bucket, o.key, err)
		}
		*o.dst = v
	}
	verify := m.Verify
	if verify == nil {
		verify = manifest.VerifyBundle
	}
	return verify(&b, ami, m.Pins)
}
