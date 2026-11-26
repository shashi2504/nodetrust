package aws

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"nodetrust/pkg/provider"
	"nodetrust/pkg/provider/conformance"
)

// fakeCloud is a small in-memory EC2 + Auto Scaling, enough for the
// containment calls. It answers with the same XML shapes as AWS and checks
// every request's SigV4 signature.
type fakeCloud struct {
	t     *testing.T
	mu    sync.Mutex
	n     int
	insts map[string]*fakeInst
	acl   []aclEntry
	snaps map[string]string // snapshot -> instance tag
	calls []string
}

type fakeInst struct {
	ip, state, group string
	enis             map[string][]string
	vols             []string
}

func newFakeCloud(t *testing.T) *fakeCloud {
	return &fakeCloud{t: t, insts: map[string]*fakeInst{}, snaps: map[string]string{},
		acl: []aclEntry{{Rule: 1000, Action: "allow", CIDR: "0.0.0.0/0"}, {Rule: 1000, Action: "allow", Egress: true, CIDR: "0.0.0.0/0"}}}
}

func (f *fakeCloud) add() provider.InstanceID {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	id := fmt.Sprintf("i-%017d", f.n)
	f.insts[id] = &fakeInst{ip: fmt.Sprintf("10.42.16.%d", f.n), state: "running", group: "nodetrust-workers",
		enis: map[string][]string{fmt.Sprintf("eni-%d", f.n): {"sg-workers"}}, vols: []string{fmt.Sprintf("vol-%da", f.n), fmt.Sprintf("vol-%db", f.n)}}
	return provider.InstanceID(id)
}

func xmlErr(w http.ResponseWriter, code string) {
	w.WriteHeader(400)
	fmt.Fprintf(w, `<Response><Errors><Error><Code>%s</Code><Message>%s</Message></Error></Errors></Response>`, code, code)
}

func (f *fakeCloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	service := "ec2"
	if strings.HasPrefix(r.Host, "as.") {
		service = "autoscaling"
	}
	checkSigned(f.t, r, body, service)
	q, _ := url.ParseQuery(string(body))
	f.mu.Lock()
	defer f.mu.Unlock()
	act := q.Get("Action")
	f.calls = append(f.calls, act)
	switch act {
	case "DescribeInstances":
		var ids []string
		if q.Get("Filter.1.Name") == "private-ip-address" {
			for id, in := range f.insts {
				if in.ip == q.Get("Filter.1.Value.1") {
					ids = append(ids, id)
				}
			}
		} else {
			ids = []string{q.Get("Filter.1.Value.1")}
		}
		fmt.Fprint(w, `<DescribeInstancesResponse><reservationSet>`)
		for _, id := range ids {
			in, ok := f.insts[id]
			if !ok {
				continue
			}
			fmt.Fprintf(w, `<item><instancesSet><item><instanceId>%s</instanceId><privateIpAddress>%s</privateIpAddress>
<instanceState><name>%s</name></instanceState><subnetId>subnet-w</subnetId><vpcId>vpc-1</vpcId>
<rootDeviceName>/dev/sda1</rootDeviceName><blockDeviceMapping>`, id, in.ip, in.state)
			for i, v := range in.vols {
				fmt.Fprintf(w, `<item><deviceName>/dev/sd%c</deviceName><ebs><volumeId>%s</volumeId></ebs></item>`, 'a'+i, v)
			}
			fmt.Fprint(w, `</blockDeviceMapping><networkInterfaceSet>`)
			for e, gs := range in.enis {
				fmt.Fprintf(w, `<item><networkInterfaceId>%s</networkInterfaceId><groupSet>`, e)
				for _, g := range gs {
					fmt.Fprintf(w, `<item><groupId>%s</groupId></item>`, g)
				}
				fmt.Fprint(w, `</groupSet></item>`)
			}
			fmt.Fprint(w, `</networkInterfaceSet></item></instancesSet></item>`)
		}
		fmt.Fprint(w, `</reservationSet></DescribeInstancesResponse>`)
	case "DeleteNetworkAclEntry":
		var n int
		fmt.Sscan(q.Get("RuleNumber"), &n)
		eg := q.Get("Egress") == "true"
		for i, e := range f.acl {
			if e.Rule == n && e.Egress == eg {
				f.acl = append(f.acl[:i], f.acl[i+1:]...)
				fmt.Fprint(w, `<DeleteNetworkAclEntryResponse><return>true</return></DeleteNetworkAclEntryResponse>`)
				return
			}
		}
		xmlErr(w, "InvalidNetworkAclEntry.NotFound")
	case "DescribeNetworkAcls":
		fmt.Fprint(w, `<DescribeNetworkAclsResponse><networkAclSet><item><entrySet>`)
		for _, e := range f.acl {
			fmt.Fprintf(w, `<item><ruleNumber>%d</ruleNumber><protocol>-1</protocol><ruleAction>%s</ruleAction><egress>%t</egress><cidrBlock>%s</cidrBlock></item>`,
				e.Rule, e.Action, e.Egress, e.CIDR)
		}
		fmt.Fprint(w, `</entrySet></item></networkAclSet></DescribeNetworkAclsResponse>`)
	case "CreateNetworkAclEntry":
		var n int
		fmt.Sscan(q.Get("RuleNumber"), &n)
		eg := q.Get("Egress") == "true"
		for _, e := range f.acl {
			if e.Rule == n && e.Egress == eg {
				xmlErr(w, "NetworkAclEntryAlreadyExists")
				return
			}
		}
		if q.Get("Protocol") != "-1" || q.Get("RuleAction") != "deny" || q.Get("NetworkAclId") != "acl-w" {
			xmlErr(w, "InvalidParameterValue")
			return
		}
		f.acl = append(f.acl, aclEntry{Rule: n, Action: "deny", Egress: eg, CIDR: q.Get("CidrBlock")})
		fmt.Fprint(w, `<CreateNetworkAclEntryResponse><return>true</return></CreateNetworkAclEntryResponse>`)
	case "ModifyNetworkInterfaceAttribute":
		for _, in := range f.insts {
			if _, ok := in.enis[q.Get("NetworkInterfaceId")]; ok {
				in.enis[q.Get("NetworkInterfaceId")] = []string{q.Get("SecurityGroupId.1")}
			}
		}
		fmt.Fprint(w, `<ModifyNetworkInterfaceAttributeResponse><return>true</return></ModifyNetworkInterfaceAttributeResponse>`)
	case "CreateTags":
		fmt.Fprint(w, `<CreateTagsResponse><return>true</return></CreateTagsResponse>`)
	case "DescribeSnapshots":
		if q.Get("Owner.1") != "self" || q.Get("Filter.1.Name") != "tag:"+TagInstance {
			xmlErr(w, "InvalidParameterValue")
			return
		}
		fmt.Fprint(w, `<DescribeSnapshotsResponse><snapshotSet>`)
		for s, id := range f.snaps {
			if id == q.Get("Filter.1.Value.1") {
				fmt.Fprintf(w, `<item><snapshotId>%s</snapshotId></item>`, s)
			}
		}
		fmt.Fprint(w, `</snapshotSet></DescribeSnapshotsResponse>`)
	case "CreateSnapshot":
		if q.Get("TagSpecification.1.Tag.1.Key") != TagInstance {
			xmlErr(w, "InvalidParameterValue")
			return
		}
		s := "snap-" + q.Get("VolumeId")
		f.snaps[s] = q.Get("TagSpecification.1.Tag.1.Value")
		fmt.Fprintf(w, `<CreateSnapshotResponse><snapshotId>%s</snapshotId></CreateSnapshotResponse>`, s)
	case "TerminateInstances":
		f.insts[q.Get("InstanceId.1")].state = "terminated"
		f.insts[q.Get("InstanceId.1")].group = ""
		fmt.Fprint(w, `<TerminateInstancesResponse></TerminateInstancesResponse>`)
	case "DescribeAutoScalingInstances":
		fmt.Fprint(w, `<DescribeAutoScalingInstancesResponse><DescribeAutoScalingInstancesResult><AutoScalingInstances>`)
		if in, ok := f.insts[q.Get("InstanceIds.member.1")]; ok && in.group != "" {
			fmt.Fprintf(w, `<member><InstanceId>%s</InstanceId><AutoScalingGroupName>%s</AutoScalingGroupName></member>`, q.Get("InstanceIds.member.1"), in.group)
		}
		fmt.Fprint(w, `</AutoScalingInstances></DescribeAutoScalingInstancesResult></DescribeAutoScalingInstancesResponse>`)
	case "DetachInstances":
		in := f.insts[q.Get("InstanceIds.member.1")]
		if q.Get("ShouldDecrementDesiredCapacity") != "false" || in == nil || in.group != q.Get("AutoScalingGroupName") {
			w.WriteHeader(400)
			fmt.Fprint(w, `<ErrorResponse><Error><Type>Sender</Type><Code>ValidationError</Code><Message>bad detach</Message></Error></ErrorResponse>`)
			return
		}
		in.group = ""
		fmt.Fprint(w, `<DetachInstancesResponse><DetachInstancesResult/></DetachInstancesResponse>`)
	default:
		xmlErr(w, "InvalidAction")
	}
}

func fakeContainment(t *testing.T) (*Containment, *fakeCloud) {
	f := newFakeCloud(t)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cr := Credentials{AccessKeyID: "ASIAEXAMPLE", SecretAccessKey: "secret", SessionToken: "session"}
	c := &Client{Region: "ap-south-1", Static: &cr, Now: func() time.Time { return fixedNow },
		EC2Endpoint: srv.URL, ASEndpoint: strings.Replace(srv.URL, "127.0.0.1", "as.localhost", 1), HTTP: srv.Client()}
	c.HTTP.Transport = &hostRewrite{base: http.DefaultTransport, to: strings.TrimPrefix(srv.URL, "http://")}
	return &Containment{C: c, QuarantineSG: "sg-quarantine", NACL: "acl-w"}, f
}

// hostRewrite sends every request to the test server but keeps the Host
// header, so the fake can tell EC2 from Auto Scaling.
type hostRewrite struct {
	base http.RoundTripper
	to   string
}

func (h *hostRewrite) RoundTrip(r *http.Request) (*http.Response, error) {
	r2 := r.Clone(r.Context())
	r2.URL.Host = h.to
	r2.Host = r.URL.Host
	return h.base.RoundTrip(r2)
}

func TestContainmentConformanceAWS(t *testing.T) {
	p, f := fakeContainment(t)
	conformance.RunContainment(t, conformance.ContainmentEnv{
		Provider:    p,
		NewInstance: func(t *testing.T) provider.InstanceID { return f.add() },
		Unknown:     "i-00000000000000000",
	})
}

func TestIsolateDeniesBothDirections(t *testing.T) {
	p, f := fakeContainment(t)
	a, b := f.add(), f.add()
	ctx := t.Context()
	for _, id := range []provider.InstanceID{a, b, a} {
		if err := p.Isolate(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	var got []string
	for _, e := range f.acl {
		if e.Action == "deny" {
			got = append(got, fmt.Sprintf("%d %t %s", e.Rule, e.Egress, e.CIDR))
		}
	}
	want := "100 false 10.42.16.1/32,100 true 10.42.16.1/32,101 false 10.42.16.2/32,101 true 10.42.16.2/32"
	if strings.Join(got, ",") != want {
		t.Fatalf("NACL denies:\n%s\nwant\n%s", strings.Join(got, ","), want)
	}
	if g := f.insts[string(a)].enis["eni-1"]; len(g) != 1 || g[0] != "sg-quarantine" {
		t.Fatalf("groups %v", g)
	}
}

func (f *fakeCloud) denies() string {
	var got []string
	for _, e := range f.acl {
		if e.Action == "deny" {
			got = append(got, fmt.Sprintf("%d %t %s", e.Rule, e.Egress, e.CIDR))
		}
	}
	return strings.Join(got, ",")
}

// Deny entries do not pile up (Phase 7 trial: NetworkAclEntryLimitExceeded):
// Terminate removes its own; an instance terminated elsewhere loses its
// entries at the next Isolate; an address reused by a fresh worker is not
// left denied.
func TestDenyEntriesRemoved(t *testing.T) {
	p, f := fakeContainment(t)
	ctx := t.Context()
	a, b, c := f.add(), f.add(), f.add()
	for _, id := range []provider.InstanceID{a, b} {
		if err := p.Isolate(ctx, id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := p.Snapshot(ctx, a, "test"); err != nil {
		t.Fatal(err)
	}
	if err := p.Terminate(ctx, a); err != nil {
		t.Fatal(err)
	}
	if got, want := f.denies(), "101 false 10.42.16.2/32,101 true 10.42.16.2/32"; got != want {
		t.Fatalf("after Terminate: %s, want %s", got, want)
	}
	// b is terminated by the Auto Scaling group; its address goes to a new
	// worker d, which is healthy.
	f.mu.Lock()
	f.insts[string(b)].state = "terminated"
	f.mu.Unlock()
	d := f.add()
	f.mu.Lock()
	f.insts[string(d)].ip = "10.42.16.2"
	f.mu.Unlock()
	if err := p.Isolate(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got, want := f.denies(), "100 false 10.42.16.3/32,100 true 10.42.16.3/32"; got != want {
		t.Fatalf("after the next Isolate: %s, want %s", got, want)
	}
	// Many contained nodes in a row stay within a few entries.
	for i := 0; i < 30; i++ {
		x := f.add()
		if err := p.Isolate(ctx, x); err != nil {
			t.Fatal(err)
		}
		if _, err := p.Snapshot(ctx, x, "t"); err != nil {
			t.Fatal(err)
		}
		if err := p.Terminate(ctx, x); err != nil {
			t.Fatal(err)
		}
	}
	if n := strings.Count(f.denies(), "/32"); n != 2 {
		t.Fatalf("%d deny entries left: %s", n, f.denies())
	}
}
