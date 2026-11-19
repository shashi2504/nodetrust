package controller

import (
	"context"
	"fmt"

	"nodetrust/pkg/nodetrust"
)

// MemKube is an in-memory API server (nodes, pods and NodeTrust objects)
// for tests and the offline demo.
type MemKube struct {
	NodeMap   map[string]*Node
	NTs       map[string]*nodetrust.Signed
	Pods      map[string][]Pod
	Calls     []string
	FailPatch error
	rv        int
}

// NewMemKube returns an empty MemKube.
func NewMemKube() *MemKube {
	return &MemKube{NodeMap: map[string]*Node{}, NTs: map[string]*nodetrust.Signed{}, Pods: map[string][]Pod{}}
}

// AddNode adds a worker node for instance id, with the join taint.
func (f *MemKube) AddNode(id string) {
	name := "ip-" + id
	f.rv++
	f.NodeMap[name] = &Node{Name: name, ProviderID: "aws:///ap-south-1c/" + id, ResourceVersion: fmt.Sprint(f.rv),
		Taints: []Taint{{Key: TaintUnattested, Effect: "NoSchedule"}}, Labels: map[string]string{}, Annotations: map[string]string{}}
}

// NodeTrusts implements Kube.
func (f *MemKube) NodeTrusts(context.Context) (map[string]*nodetrust.Signed, error) {
	out := map[string]*nodetrust.Signed{}
	for k, v := range f.NTs {
		out[k] = v
	}
	return out, nil
}

// Nodes implements Kube.
func (f *MemKube) Nodes(context.Context) ([]Node, error) {
	var out []Node
	for _, n := range f.NodeMap {
		out = append(out, *n)
	}
	return out, nil
}

// PatchNode implements Kube.
func (f *MemKube) PatchNode(_ context.Context, n Node, taints []Taint, unsched bool, ann map[string]*string) error {
	if f.FailPatch != nil {
		return f.FailPatch
	}
	cur := f.NodeMap[n.Name]
	if cur == nil || cur.ResourceVersion != n.ResourceVersion {
		return fmt.Errorf("409 conflict")
	}
	cur.Taints, cur.Unschedulable = taints, unsched
	for k, v := range ann {
		if v == nil {
			delete(cur.Annotations, k)
		} else {
			cur.Annotations[k] = *v
		}
	}
	f.rv++
	cur.ResourceVersion = fmt.Sprint(f.rv)
	f.Calls = append(f.Calls, "patch "+n.Name)
	return nil
}

// DeleteNode implements Kube.
func (f *MemKube) DeleteNode(_ context.Context, name string) error {
	delete(f.NodeMap, name)
	f.Calls = append(f.Calls, "delete "+name)
	return nil
}

// PodsOn implements Kube.
func (f *MemKube) PodsOn(_ context.Context, node string) ([]Pod, error) { return f.Pods[node], nil }

// Evict implements Kube.
func (f *MemKube) Evict(_ context.Context, ns, name string) error {
	f.Calls = append(f.Calls, "evict "+ns+"/"+name)
	return nil
}
