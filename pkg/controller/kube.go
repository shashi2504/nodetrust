package controller

// The controller's Kubernetes calls, over the same standard-library client
// the verifier uses (pkg/nodetrust.Kube).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"

	"nodetrust/pkg/nodetrust"
)

// KubeAPI implements Kube against a real API server.
type KubeAPI struct{ K *nodetrust.Kube }

var _ Kube = KubeAPI{}

func (a KubeAPI) get(ctx context.Context, path string, out any) error {
	b, code, err := a.K.Do(ctx, http.MethodGet, path, "", nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return nodetrust.APIError("get "+path, code, b)
	}
	return json.Unmarshal(b, out)
}

// NodeTrusts implements Kube.
func (a KubeAPI) NodeTrusts(ctx context.Context) (map[string]*nodetrust.Signed, error) {
	var l struct {
		Items []struct {
			Metadata struct{ Name string } `json:"metadata"`
			Status   struct {
				Signed *nodetrust.Signed `json:"signed"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := a.get(ctx, "/apis/"+nodetrust.Group+"/"+nodetrust.Version+"/"+nodetrust.Resource, &l); err != nil {
		return nil, err
	}
	out := map[string]*nodetrust.Signed{}
	for _, it := range l.Items {
		out[it.Metadata.Name] = it.Status.Signed
	}
	return out, nil
}

type kubeMeta struct {
	Name            string            `json:"name"`
	Namespace       string            `json:"namespace"`
	ResourceVersion string            `json:"resourceVersion"`
	Labels          map[string]string `json:"labels"`
	Annotations     map[string]string `json:"annotations"`
}

// Nodes implements Kube.
func (a KubeAPI) Nodes(ctx context.Context) ([]Node, error) {
	var l struct {
		Items []struct {
			Metadata kubeMeta `json:"metadata"`
			Spec     struct {
				ProviderID    string  `json:"providerID"`
				Taints        []Taint `json:"taints"`
				Unschedulable bool    `json:"unschedulable"`
			} `json:"spec"`
		} `json:"items"`
	}
	if err := a.get(ctx, "/api/v1/nodes", &l); err != nil {
		return nil, err
	}
	var out []Node
	for _, it := range l.Items {
		out = append(out, Node{Name: it.Metadata.Name, ProviderID: it.Spec.ProviderID, ResourceVersion: it.Metadata.ResourceVersion,
			Taints: it.Spec.Taints, Unschedulable: it.Spec.Unschedulable, Labels: it.Metadata.Labels, Annotations: it.Metadata.Annotations})
	}
	return out, nil
}

// PatchNode implements Kube with a JSON merge patch that carries the
// resourceVersion, so it fails (409) if the node changed in between.
func (a KubeAPI) PatchNode(ctx context.Context, n Node, taints []Taint, unschedulable bool, ann map[string]*string) error {
	if taints == nil {
		taints = []Taint{}
	}
	meta := map[string]any{"resourceVersion": n.ResourceVersion}
	if len(ann) > 0 {
		meta["annotations"] = ann
	}
	patch := map[string]any{"metadata": meta, "spec": map[string]any{"taints": taints, "unschedulable": unschedulable}}
	b, code, err := a.K.Do(ctx, http.MethodPatch, "/api/v1/nodes/"+url.PathEscape(n.Name), "application/merge-patch+json", patch)
	if err != nil {
		return err
	}
	if code/100 != 2 {
		return nodetrust.APIError("patch node "+n.Name, code, b)
	}
	return nil
}

// DeleteNode implements Kube (a node already gone is not an error).
func (a KubeAPI) DeleteNode(ctx context.Context, name string) error {
	b, code, err := a.K.Do(ctx, http.MethodDelete, "/api/v1/nodes/"+url.PathEscape(name), "", nil)
	if err != nil {
		return err
	}
	if code/100 != 2 && code != http.StatusNotFound {
		return nodetrust.APIError("delete node "+name, code, b)
	}
	return nil
}

// PodsOn implements Kube.
func (a KubeAPI) PodsOn(ctx context.Context, node string) ([]Pod, error) {
	var l struct {
		Items []struct {
			Metadata kubeMeta `json:"metadata"`
			Spec     struct {
				ServiceAccount string `json:"serviceAccountName"`
				Volumes        []struct {
					Secret *struct {
						Name string `json:"secretName"`
					} `json:"secret"`
					Projected *struct {
						Sources []struct {
							Secret *struct {
								Name string `json:"name"`
							} `json:"secret"`
						} `json:"sources"`
					} `json:"projected"`
				} `json:"volumes"`
			} `json:"spec"`
		} `json:"items"`
	}
	q := url.Values{"fieldSelector": {"spec.nodeName=" + node}}
	if err := a.get(ctx, "/api/v1/pods?"+q.Encode(), &l); err != nil {
		return nil, err
	}
	var out []Pod
	for _, it := range l.Items {
		p := Pod{Namespace: it.Metadata.Namespace, Name: it.Metadata.Name, Labels: it.Metadata.Labels, ServiceAccount: it.Spec.ServiceAccount}
		for _, v := range it.Spec.Volumes {
			if v.Secret != nil {
				p.Secrets = append(p.Secrets, v.Secret.Name)
			}
			if v.Projected != nil {
				for _, s := range v.Projected.Sources {
					if s.Secret != nil {
						p.Secrets = append(p.Secrets, s.Secret.Name)
					}
				}
			}
		}
		out = append(out, p)
	}
	return out, nil
}

// Evict implements Kube with the Eviction API, which respects
// PodDisruptionBudgets (a 429 is returned as an error and retried).
func (a KubeAPI) Evict(ctx context.Context, namespace, name string) error {
	body := map[string]any{"apiVersion": "policy/v1", "kind": "Eviction",
		"metadata": map[string]string{"name": name, "namespace": namespace}}
	b, code, err := a.K.Do(ctx, http.MethodPost, "/api/v1/namespaces/"+url.PathEscape(namespace)+"/pods/"+url.PathEscape(name)+"/eviction",
		"application/json", body)
	if err != nil {
		return err
	}
	if code/100 != 2 && code != http.StatusNotFound {
		return nodetrust.APIError("evict "+namespace+"/"+name, code, b)
	}
	return nil
}
