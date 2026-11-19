package controller

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nodetrust/pkg/nodetrust"
)

// The requests the controller sends to a real API server: paths, content
// types and bodies.
func TestKubeAPIRequests(t *testing.T) {
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = append(got, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("Content-Type")+" "+string(b))
		switch {
		case r.URL.Path == "/api/v1/nodes":
			w.Write([]byte(`{"items":[{"metadata":{"name":"ip-1","resourceVersion":"7","labels":{"a":"b"}},
			  "spec":{"providerID":"aws:///ap-south-1c/i-0abc","unschedulable":true,
			  "taints":[{"key":"trust.k8s-attest.io/unattested","effect":"NoSchedule"}]}}]}`))
		case r.URL.Path == "/api/v1/pods":
			w.Write([]byte(`{"items":[{"metadata":{"namespace":"prod","name":"db","labels":{"trust.k8s-attest.io/sensitive":"true"}},
			  "spec":{"serviceAccountName":"db","volumes":[{"secret":{"secretName":"pw"}},
			  {"projected":{"sources":[{"secret":{"name":"tls"}},{"serviceAccountToken":{}}]}}]}}]}`))
		case strings.HasPrefix(r.URL.Path, "/apis/"):
			w.Write([]byte(`{"items":[{"metadata":{"name":"i-0abc"},"status":{"signed":{"payload":"cA==","signature":"cw==","keyID":"k"}}}]}`))
		case r.Method == http.MethodDelete:
			w.WriteHeader(404)
		default:
			w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()
	a := KubeAPI{K: &nodetrust.Kube{Server: srv.URL, HTTP: srv.Client()}}
	ctx := context.Background()

	nts, err := a.NodeTrusts(ctx)
	if err != nil || nts["i-0abc"] == nil || nts["i-0abc"].KeyID != "k" {
		t.Fatalf("NodeTrusts %v %v", nts, err)
	}
	ns, err := a.Nodes(ctx)
	if err != nil || len(ns) != 1 || ns[0].InstanceID() != "i-0abc" || !ns[0].Unschedulable || len(ns[0].Taints) != 1 {
		t.Fatalf("Nodes %+v %v", ns, err)
	}
	v := "nodetrust"
	if err := a.PatchNode(ctx, ns[0], nil, true, map[string]*string{AnnCordoned: &v}); err != nil {
		t.Fatal(err)
	}
	pods, err := a.PodsOn(ctx, "ip-1")
	if err != nil || len(pods) != 1 || strings.Join(pods[0].Secrets, ",") != "pw,tls" || pods[0].ServiceAccount != "db" {
		t.Fatalf("pods %+v %v", pods, err)
	}
	if err := a.Evict(ctx, "prod", "db"); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteNode(ctx, "ip-1"); err != nil {
		t.Fatalf("a missing node is not an error: %v", err)
	}
	want := []string{
		"GET /apis/trust.k8s-attest.io/v1alpha1/nodetrusts  ",
		"GET /api/v1/nodes  ",
		`PATCH /api/v1/nodes/ip-1 application/merge-patch+json {"metadata":{"annotations":{"trust.k8s-attest.io/cordoned-by":"nodetrust"},"resourceVersion":"7"},"spec":{"taints":[],"unschedulable":true}}`,
		"GET /api/v1/pods?fieldSelector=spec.nodeName%3Dip-1  ",
		`POST /api/v1/namespaces/prod/pods/db/eviction application/json {"apiVersion":"policy/v1","kind":"Eviction","metadata":{"name":"db","namespace":"prod"}}`,
		"DELETE /api/v1/nodes/ip-1  ",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
