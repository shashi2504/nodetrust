package nodetrust

// A minimal Kubernetes API client for the verifier: server-side apply of
// NodeTrust objects and their status, and delete. Standard library only
// (client-go cannot be fetched in this build environment).

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// FieldManager is the verifier's server-side apply field manager.
const FieldManager = "nodetrust-verifier"

// Kube talks to one API server with a client certificate.
type Kube struct {
	Server string // https://host:6443
	HTTP   *http.Client
}

// NewKube pins the cluster CA and presents the client certificate.
func NewKube(server string, caPEM, certPEM, keyPEM []byte) (*Kube, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("kube: no CA certificate")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("kube: client certificate: %w", err)
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}},
		TLSHandshakeTimeout: 10 * time.Second}
	return &Kube{Server: server, HTTP: &http.Client{Transport: tr, Timeout: 20 * time.Second}}, nil
}

func (k *Kube) path(name, sub string) string {
	p := "/apis/" + Group + "/" + Version + "/" + Resource
	if name != "" {
		p += "/" + url.PathEscape(name)
	}
	if sub != "" {
		p += "/" + sub
	}
	return p
}

func (k *Kube) do(ctx context.Context, method, path, ctype string, body any) ([]byte, int, error) {
	var r io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.Server+path, r)
	if err != nil {
		return nil, 0, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return out, resp.StatusCode, err
}

func apiError(op string, code int, body []byte) error {
	var st struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &st)
	if st.Message == "" {
		st.Message = string(bytes.TrimSpace(body))
	}
	return fmt.Errorf("kube %s: %d %s", op, code, st.Message)
}

// Apply creates or updates a NodeTrust object and then its status, with
// server-side apply (the status is a subresource, so it takes its own call).
func (k *Kube) Apply(ctx context.Context, obj map[string]any) error {
	name := obj["metadata"].(map[string]any)["name"].(string)
	q := "?fieldManager=" + FieldManager + "&force=true"
	main := map[string]any{"apiVersion": obj["apiVersion"], "kind": obj["kind"], "metadata": obj["metadata"], "spec": obj["spec"]}
	if b, code, err := k.do(ctx, http.MethodPatch, k.path(name, "")+q, "application/apply-patch+yaml", main); err != nil {
		return err
	} else if code/100 != 2 {
		return apiError("apply "+name, code, b)
	}
	status := map[string]any{"apiVersion": obj["apiVersion"], "kind": obj["kind"], "metadata": obj["metadata"], "status": obj["status"]}
	if b, code, err := k.do(ctx, http.MethodPatch, k.path(name, "status")+q, "application/apply-patch+yaml", status); err != nil {
		return err
	} else if code/100 != 2 {
		return apiError("apply status "+name, code, b)
	}
	return nil
}

// Delete removes a NodeTrust object; a missing one is not an error.
func (k *Kube) Delete(ctx context.Context, name string) error {
	b, code, err := k.do(ctx, http.MethodDelete, k.path(name, ""), "", nil)
	if err != nil {
		return err
	}
	if code/100 != 2 && code != http.StatusNotFound {
		return apiError("delete "+name, code, b)
	}
	return nil
}

// Get reads one NodeTrust object's signed state (nil if it has none).
func (k *Kube) Get(ctx context.Context, name string) (*Signed, error) {
	b, code, err := k.do(ctx, http.MethodGet, k.path(name, ""), "", nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, apiError("get "+name, code, b)
	}
	var o struct {
		Status struct {
			Signed *Signed `json:"signed"`
		} `json:"status"`
	}
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, err
	}
	return o.Status.Signed, nil
}

// Publisher signs states and applies them.
type Publisher struct {
	Kube *Kube
	Key  *ecdsa.PrivateKey
}

// Publish signs and applies one state.
func (p *Publisher) Publish(ctx context.Context, st *State) error {
	s, err := Sign(p.Key, st)
	if err != nil {
		return err
	}
	return p.Kube.Apply(ctx, Object(st, s))
}

// Remove deletes a node's object (the instance is gone).
func (p *Publisher) Remove(ctx context.Context, id string) error { return p.Kube.Delete(ctx, id) }

// Do sends one request to the API server with the client's certificate and
// returns the body and status code (for the trust controller's calls).
func (k *Kube) Do(ctx context.Context, method, path, ctype string, body any) ([]byte, int, error) {
	return k.do(ctx, method, path, ctype, body)
}

// APIError builds an error from a failed API server response.
func APIError(op string, code int, body []byte) error { return apiError(op, code, body) }
