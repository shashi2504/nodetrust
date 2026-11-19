package aws

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"nodetrust/pkg/manifest"
)

func TestInventory(t *testing.T) {
	var n int32
	c := newTestClient(t, nil, &n)
	ws, err := (&Inventory{C: c, Filters: map[string][]string{"tag:role": {"worker"}}, AgentPort: 9443}).Workers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	w := ws[0]
	if w.InstanceID != "i-079cec283e5944e99" || w.Addr != "10.42.18.108:9443" || w.AMI != "ami-02dc3031448c845a0" || w.RootVolumeID != "vol-084c34c32fbb06e85" {
		t.Fatalf("%+v", w)
	}
}

func TestManifestStore(t *testing.T) {
	var gets int32
	objects := map[string]string{
		"/bkt/signed/ami-1/statement.json":        "st",
		"/bkt/signed/ami-1/statement.sig":         "sig",
		"/bkt/signed/ami-1/rekor-entry.json":      "rekor",
		"/bkt/manifests/ami-1/manifest.json.gz":   "gz",
		"/bkt/signed/ami-bad/statement.json":      "st",
		"/bkt/signed/ami-bad/statement.sig":       "sig",
		"/bkt/signed/ami-bad/rekor-entry.json":    "rekor",
		"/bkt/manifests/ami-bad/manifest.json.gz": "gz",
	}
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&gets, 1)
		if v, ok := objects[r.URL.Path]; ok {
			fmt.Fprint(w, v)
			return
		}
		w.WriteHeader(404)
		fmt.Fprint(w, `<Error><Code>NoSuchKey</Code></Error>`)
	}))
	defer s3.Close()
	c := &Client{Region: "ap-south-1", S3Endpoint: s3.URL, Static: &Credentials{AccessKeyID: "A", SecretAccessKey: "S"}}
	var verified []string
	m := &ManifestStore{C: c, Bucket: "bkt", RetryAfter: time.Hour,
		Verify: func(b *manifest.Bundle, ami string, _ manifest.Pins) (*manifest.Trusted, error) {
			verified = append(verified, ami)
			if string(b.Statement) != "st" || string(b.Signature) != "sig" || string(b.RekorEntry) != "rekor" || string(b.Manifest) != "gz" {
				t.Errorf("bundle %+v", b)
			}
			if ami == "ami-bad" {
				return nil, errors.New("signature does not verify")
			}
			return &manifest.Trusted{}, nil
		}}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := m.Trusted(ctx, "ami-1"); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Trusted(ctx, "ami-bad"); err == nil {
			t.Fatal("bad bundle accepted")
		}
	}
	if len(verified) != 2 || gets != 8 {
		t.Fatalf("verified %v, %d GETs: want each AMI fetched and verified once", verified, gets)
	}
	if _, err := m.Trusted(ctx, "ami-missing"); err == nil {
		t.Fatal("missing bundle accepted")
	}
}
