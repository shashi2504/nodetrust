package aws

// The AWS containment provider: the out-of-band steps of the critical path
// (blueprint 8.3), done with the trust controller's IAM role through the EC2
// and Auto Scaling APIs. Nothing here needs the instance's cooperation.
//
//	Isolate   every ENI gets only the empty quarantine security group, and
//	          the network ACL of the other subnets (control plane, verifier,
//	          NAT) gets deny entries for the instance's IP in both
//	          directions. The ACL is stateless, so it also cuts connections
//	          the security group was still tracking.
//
// Why the other subnets' ACL: an ACL rule matches the remote address
// (inbound: source, outbound: destination). On the worker's own subnet a
// rule for the worker's IP never matches its traffic; on the subnets it
// talks to, "inbound from W" and "outbound to W" do. Traffic between two
// workers in the same subnet passes no ACL; the security group swap stops
// new flows there (blueprint 8.3 adds a peer-side DaemonSet for the rest).
//	Snapshot  every attached EBS volume, tagged with the instance and reason
//	Replace   detach from the Auto Scaling group without lowering the
//	          desired capacity, so the group launches a clean node; the
//	          quarantined instance keeps running for forensics
//	Terminate only after the snapshots exist (operator approval is the
//	          controller's job); removes the instance's deny entries
//
// Deny entries whose address no longer belongs to a quarantined instance
// are removed by Isolate and Terminate (see prune).
//
// Every step reads the current state first, so repeating a step that
// already happened does nothing.

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"nodetrust/pkg/provider"
)

// Tags the provider puts on snapshots and the instance.
const (
	TagInstance = "nodetrust:instance"
	TagReason   = "nodetrust:reason"
	TagPhase    = "nodetrust:containment"
)

// NACL rule numbers the controller may use; the infra NACL allows
// everything at rule 1000 (infra/cluster/network.tf).
const (
	firstDenyRule = 100
	lastDenyRule  = 999
)

// Containment implements provider.ContainmentProvider for EC2 workers.
type Containment struct {
	C            *Client
	QuarantineSG string // empty security group in the workers' VPC
	NACL         string // network ACL of the control plane, verifier and public subnets
}

var _ provider.ContainmentProvider = (*Containment)(nil)

func (p *Containment) instance(ctx context.Context, id provider.InstanceID) (*Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ins, err := p.C.DescribeInstances(ctx, map[string][]string{"instance-id": {string(id)}})
	if err != nil {
		return nil, err
	}
	if len(ins) == 0 {
		return nil, fmt.Errorf("%w: %s", provider.ErrNotFound, id)
	}
	return &ins[0], nil
}

func gone(in *Instance) bool { return in.State == "terminated" || in.State == "shutting-down" }

// aclEntry is one network ACL rule.
type aclEntry struct {
	Rule   int    `xml:"ruleNumber"`
	Action string `xml:"ruleAction"`
	Egress bool   `xml:"egress"`
	CIDR   string `xml:"cidrBlock"`
}

func (p *Containment) aclEntries(ctx context.Context) ([]aclEntry, error) {
	var r struct {
		Entries []aclEntry `xml:"networkAclSet>item>entrySet>item"`
	}
	err := p.C.ec2(ctx, url.Values{"Action": {"DescribeNetworkAcls"}, "NetworkAclId.1": {p.NACL}}, &r)
	return r.Entries, err
}

// denied reports which directions already have a deny entry for cidr.
func denied(es []aclEntry, cidr string) (in, out bool) {
	for _, e := range es {
		if e.CIDR == cidr && e.Action == "deny" && e.Rule < 1000 {
			if e.Egress {
				out = true
			} else {
				in = true
			}
		}
	}
	return in, out
}

// freeRule is the lowest unused deny rule number in one direction.
func freeRule(es []aclEntry, egress bool) (int, error) {
	used := map[int]bool{}
	for _, e := range es {
		if e.Egress == egress {
			used[e.Rule] = true
		}
	}
	for n := firstDenyRule; n <= lastDenyRule; n++ {
		if !used[n] {
			return n, nil
		}
	}
	return 0, errors.New("aws: no free network ACL rule number")
}

// quarantined reports whether every ENI of the instance has only the
// quarantine group.
func (p *Containment) quarantined(in *Instance) bool {
	if len(in.ENIs) == 0 {
		return false
	}
	for _, e := range in.ENIs {
		if len(e.Groups) != 1 || e.Groups[0] != p.QuarantineSG {
			return false
		}
	}
	return true
}

// prune deletes the deny entries whose address no longer belongs to a
// quarantined instance: the instance was terminated (by Terminate, the
// Auto Scaling group or an operator), or its address went to a new worker,
// which must not inherit the deny. keep is an address being isolated right
// now. Without this the entries pile up until the ACL is full (20 rules a
// direction by default; the Phase 7 trial hit NetworkAclEntryLimitExceeded
// after about 18 contained runs).
func (p *Containment) prune(ctx context.Context, es []aclEntry, keep string) ([]aclEntry, error) {
	var left []aclEntry
	held := map[string]bool{}
	for _, e := range es {
		if e.Action != "deny" || e.Rule < firstDenyRule || e.Rule > lastDenyRule || e.CIDR == keep {
			left = append(left, e)
			continue
		}
		ok, seen := held[e.CIDR]
		if !seen {
			ins, err := p.C.DescribeInstances(ctx, map[string][]string{"private-ip-address": {strings.TrimSuffix(e.CIDR, "/32")}})
			if err != nil {
				return es, err
			}
			for i := range ins {
				if !gone(&ins[i]) && p.quarantined(&ins[i]) {
					ok = true
				}
			}
			held[e.CIDR] = ok
		}
		if ok {
			left = append(left, e)
			continue
		}
		err := p.C.ec2(ctx, url.Values{"Action": {"DeleteNetworkAclEntry"}, "NetworkAclId": {p.NACL},
			"RuleNumber": {strconv.Itoa(e.Rule)}, "Egress": {strconv.FormatBool(e.Egress)}}, nil)
		if err != nil {
			return es, fmt.Errorf("aws: remove stale NACL deny for %s: %w", e.CIDR, err)
		}
	}
	return left, nil
}

func (p *Containment) isolated(ctx context.Context, in *Instance) (bool, error) {
	for _, e := range in.ENIs {
		if len(e.Groups) != 1 || e.Groups[0] != p.QuarantineSG {
			return false, nil
		}
	}
	if in.PrivateIP == "" || len(in.ENIs) == 0 {
		return false, nil
	}
	es, err := p.aclEntries(ctx)
	if err != nil {
		return false, err
	}
	i, o := denied(es, in.PrivateIP+"/32")
	return i && o, nil
}

// Isolate implements provider.ContainmentProvider.
func (p *Containment) Isolate(ctx context.Context, id provider.InstanceID) error {
	in, err := p.instance(ctx, id)
	if err != nil {
		return err
	}
	if gone(in) {
		return fmt.Errorf("%w: %s is %s", provider.ErrPrecondition, id, in.State)
	}
	if p.QuarantineSG == "" || p.NACL == "" {
		return errors.New("aws: quarantine security group or network ACL not configured")
	}
	// The NACL first: it cuts existing flows at once, the group swap does not.
	if in.PrivateIP == "" {
		return fmt.Errorf("aws: %s has no private IP", id)
	}
	cidr := in.PrivateIP + "/32"
	es, err := p.aclEntries(ctx)
	if err != nil {
		return err
	}
	if es, err = p.prune(ctx, es, cidr); err != nil {
		return err
	}
	hasIn, hasOut := denied(es, cidr)
	for _, egress := range []bool{false, true} {
		if (!egress && hasIn) || (egress && hasOut) {
			continue
		}
		n, err := freeRule(es, egress)
		if err != nil {
			return err
		}
		err = p.C.ec2(ctx, url.Values{"Action": {"CreateNetworkAclEntry"}, "NetworkAclId": {p.NACL},
			"RuleNumber": {strconv.Itoa(n)}, "Protocol": {"-1"}, "RuleAction": {"deny"},
			"Egress": {strconv.FormatBool(egress)}, "CidrBlock": {cidr}}, nil)
		if err != nil {
			return fmt.Errorf("aws: NACL deny for %s: %w", cidr, err)
		}
		es = append(es, aclEntry{Rule: n, Action: "deny", Egress: egress, CIDR: cidr})
	}
	for _, e := range in.ENIs {
		if len(e.Groups) == 1 && e.Groups[0] == p.QuarantineSG {
			continue
		}
		err := p.C.ec2(ctx, url.Values{"Action": {"ModifyNetworkInterfaceAttribute"},
			"NetworkInterfaceId": {e.ID}, "SecurityGroupId.1": {p.QuarantineSG}}, nil)
		if err != nil {
			return fmt.Errorf("aws: quarantine group on %s: %w", e.ID, err)
		}
	}
	return p.tag(ctx, string(id), map[string]string{TagPhase: "isolated"})
}

func (p *Containment) tag(ctx context.Context, res string, tags map[string]string) error {
	form := url.Values{"Action": {"CreateTags"}, "ResourceId.1": {res}}
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for i, k := range keys {
		form.Set("Tag."+strconv.Itoa(i+1)+".Key", k)
		form.Set("Tag."+strconv.Itoa(i+1)+".Value", tags[k])
	}
	return p.C.ec2(ctx, form, nil)
}

func (p *Containment) snapshots(ctx context.Context, id provider.InstanceID) ([]provider.SnapshotID, error) {
	var r struct {
		IDs []string `xml:"snapshotSet>item>snapshotId"`
	}
	err := p.C.ec2(ctx, url.Values{"Action": {"DescribeSnapshots"}, "Owner.1": {"self"},
		"Filter.1.Name": {"tag:" + TagInstance}, "Filter.1.Value.1": {string(id)}}, &r)
	if err != nil {
		return nil, err
	}
	sort.Strings(r.IDs)
	out := make([]provider.SnapshotID, len(r.IDs))
	for i, s := range r.IDs {
		out[i] = provider.SnapshotID(s)
	}
	return out, nil
}

// Snapshot implements provider.ContainmentProvider.
func (p *Containment) Snapshot(ctx context.Context, id provider.InstanceID, reason string) ([]provider.SnapshotID, error) {
	in, err := p.instance(ctx, id)
	if err != nil {
		return nil, err
	}
	if gone(in) {
		return nil, fmt.Errorf("%w: %s is %s", provider.ErrPrecondition, id, in.State)
	}
	have, err := p.snapshots(ctx, id)
	if err != nil || len(have) > 0 {
		return have, err
	}
	if len(in.Volumes) == 0 {
		return nil, fmt.Errorf("aws: %s has no EBS volumes", id)
	}
	if len(reason) > 250 {
		reason = reason[:250]
	}
	var out []provider.SnapshotID
	for _, v := range in.Volumes {
		var r struct {
			ID string `xml:"snapshotId"`
		}
		err := p.C.ec2(ctx, url.Values{"Action": {"CreateSnapshot"}, "VolumeId": {v},
			"Description":                     {"nodetrust evidence: " + string(id)},
			"TagSpecification.1.ResourceType": {"snapshot"},
			"TagSpecification.1.Tag.1.Key":    {TagInstance}, "TagSpecification.1.Tag.1.Value": {string(id)},
			"TagSpecification.1.Tag.2.Key": {TagReason}, "TagSpecification.1.Tag.2.Value": {reason},
			"TagSpecification.1.Tag.3.Key": {"Name"}, "TagSpecification.1.Tag.3.Value": {"nodetrust-evidence-" + string(id)},
		}, &r)
		if err != nil {
			return out, fmt.Errorf("aws: snapshot of %s: %w", v, err)
		}
		out = append(out, provider.SnapshotID(r.ID))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, p.tag(ctx, string(id), map[string]string{TagPhase: "snapshotted"})
}

// group returns the Auto Scaling group the instance is in, or "".
func (p *Containment) group(ctx context.Context, id provider.InstanceID) (string, error) {
	var r struct {
		Instances []struct {
			Group string `xml:"AutoScalingGroupName"`
		} `xml:"DescribeAutoScalingInstancesResult>AutoScalingInstances>member"`
	}
	err := p.C.autoscaling(ctx, url.Values{"Action": {"DescribeAutoScalingInstances"}, "InstanceIds.member.1": {string(id)}}, &r)
	if err != nil || len(r.Instances) == 0 {
		return "", err
	}
	return r.Instances[0].Group, nil
}

// Replace implements provider.ContainmentProvider.
func (p *Containment) Replace(ctx context.Context, id provider.InstanceID) error {
	in, err := p.instance(ctx, id)
	if err != nil {
		return err
	}
	if gone(in) {
		return fmt.Errorf("%w: %s is %s", provider.ErrPrecondition, id, in.State)
	}
	if ok, err := p.isolated(ctx, in); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%w: %s is not isolated", provider.ErrPrecondition, id)
	}
	g, err := p.group(ctx, id)
	if err != nil || g == "" {
		return err // not in a group any more: already replaced
	}
	err = p.C.autoscaling(ctx, url.Values{"Action": {"DetachInstances"}, "AutoScalingGroupName": {g},
		"InstanceIds.member.1": {string(id)}, "ShouldDecrementDesiredCapacity": {"false"}}, nil)
	if err != nil {
		return fmt.Errorf("aws: detach %s from %s: %w", id, g, err)
	}
	return p.tag(ctx, string(id), map[string]string{TagPhase: "replaced"})
}

// Terminate implements provider.ContainmentProvider.
func (p *Containment) Terminate(ctx context.Context, id provider.InstanceID) error {
	in, err := p.instance(ctx, id)
	if err != nil {
		return err
	}
	if gone(in) {
		return nil
	}
	snaps, err := p.snapshots(ctx, id)
	if err != nil {
		return err
	}
	if len(snaps) == 0 {
		return fmt.Errorf("%w: %s has no evidence snapshot", provider.ErrPrecondition, id)
	}
	if err := p.C.ec2(ctx, url.Values{"Action": {"TerminateInstances"}, "InstanceId.1": {string(id)}}, nil); err != nil {
		return err
	}
	// Its deny entries go now; any others left by instances terminated
	// elsewhere go with them.
	es, err := p.aclEntries(ctx)
	if err != nil {
		return err
	}
	_, err = p.prune(ctx, es, "")
	return err
}

// State implements provider.ContainmentProvider.
func (p *Containment) State(ctx context.Context, id provider.InstanceID) (provider.State, error) {
	var st provider.State
	in, err := p.instance(ctx, id)
	if err != nil {
		return st, err
	}
	if st.Terminated = gone(in); st.Terminated {
		st.Isolated, st.Replaced = true, true
	} else {
		if st.Isolated, err = p.isolated(ctx, in); err != nil {
			return st, err
		}
		g, err := p.group(ctx, id)
		if err != nil {
			return st, err
		}
		st.Replaced = g == "" // workers start in the group; out of it means detached
	}
	st.Snapshots, err = p.snapshots(ctx, id)
	return st, err
}
