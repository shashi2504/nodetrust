# Phase 5: trust controller

The verifier decides how far each node can be trusted and publishes it as
a signed NodeTrust object (Phase 4). The trust controller turns that into
actions in the cluster and in AWS (blueprint Section 8). Code:
`pkg/controller`, `pkg/provider/aws/containment.go`, `cmd/controller`.

## What it does

Every 5 seconds it lists the NodeTrust objects and the Nodes. For each
NodeTrust it checks the signature against the pinned public key, that the
object holds the state of its own instance, and that the sequence number
went up. An update that fails is counted and ignored, and the last good
state stays in force, so a forged or replayed object changes nothing.

Then for each worker (matched by its provider ID, aws:///zone/instance):

| Signed state | Action |
| --- | --- |
| no valid NodeTrust yet | keep `trust.k8s-attest.io/unattested:NoSchedule` (set at join) |
| unattested, or no fresh update | `unattested:NoSchedule` |
| healthy | no trust taints; uncordon if the controller cordoned it |
| warning | `warning:PreferNoSchedule` |
| degraded | `degraded:NoSchedule`, cordon, evict pods labelled `trust.k8s-attest.io/sensitive=true` |
| untrusted or critical | the critical path |

The critical path (8.3), all in the same round:

1. cordon and taint `critical:NoExecute`; record every Secret and service
   account the node's pods use, for rotation
2. isolate: every ENI gets only the empty quarantine security group, and
   the network ACL of the control plane, verifier and public (NAT) subnets
   gets deny entries for the node's IP in both directions
3. snapshot every EBS volume, tagged with the instance and the finding
4. detach the instance from the Auto Scaling group without lowering the
   desired capacity, so a clean node is launched; the quarantined instance
   keeps running for forensics
5. delete the Node object, so the pods are recreated elsewhere

A critical node is never returned to service. Terminating it is a separate
operator command (`nodetrust-controller terminate`), allowed only after the
snapshots exist.

Safety controls (8.4):

- Verifier outage: if no node has a fresh NodeTrust update (3 minutes), the
  controller assumes the verifier or the network is down and starts nothing
  new. A single silent node while the others are fresh gets the unattested
  taint.
- Circuit breaker: if more than 2 nodes, or more than 30% of the workers,
  went critical in 10 minutes, steps 2-5 wait for an operator
  (`nodetrust-controller approve -instance i-...`). Step 1 still happens.
  With two workers one critical node is already 50%, so the live test also
  shows the breaker and the approval.
- Dry run: `dry_run: true` logs every action ("dry-run: would ...") and
  changes nothing.

Only the controller may write trust taints: the `nodetrust-taints`
admission policy denies any other user who adds, changes or removes a
`trust.k8s-attest.io/` taint.

## Where it runs and what it may do

The controller runs as a systemd service on the control plane host, with
that host's IAM role, not as a Deployment: the cluster has no image
registry, and the blueprint wants the critical path through the AWS API
anyway. It logs in to the API server with its own client certificate (CN
nodetrust-controller, from Terraform). RBAC (`k8s/controller.yaml`): read
NodeTrust, patch and delete Nodes, list pods, evict pods. It cannot write
NodeTrust.

IAM (`infra/cluster/controller.tf`): describe instances, network ACLs,
snapshots and group membership; swap security groups on ENIs to the
quarantine group; add entries to the infra network ACL; create snapshots
and tags; detach from the worker group; terminate only instances tagged as
contained. Workers have none of these.

## Why the ACL denies go on the other subnets

A network ACL rule matches the remote address: inbound rules match the
source, outbound rules match the destination. A rule for the worker's own
IP on the worker's subnet ACL would never match its traffic. On the subnets
it talks to (control plane, verifier, NAT), "inbound from the worker" and
"outbound to the worker" match, and because the ACL is stateless they also
cut connections the security group was still tracking. The original plan
(denies on the worker subnet's ACL) was found wrong while writing this
step; `infra/cluster/network.tf` now gives the other three subnets their
own ACL for this.

Not done yet: traffic between two workers in the same subnet passes no ACL.
The security group swap stops new connections; the blueprint's peer-side
DaemonSet (drop the node's IP in nftables on healthy nodes) needs a
container image and is future work.

## Run

After Phase 4 (verifier deployed, workers healthy):

```
cd infra/cluster && terraform apply        # controller cert, quarantine group, infra ACL, IAM
cd ../phase4 && ./replace-workers.sh
cd ../phase5
DRY_RUN=1 ./deploy-controller.sh && ./check-controller.sh     # dry run, about 8 minutes
cd ../phase4 && ./replace-workers.sh && cd ../phase5
DRY_RUN=0 ./deploy-controller.sh && ./check-controller.sh     # live, about 20 minutes
```

check-controller.sh reads the mode from the controller's status. Dry run:
the expected "would ..." lines for healthy, warning and critical nodes (and
after approval the isolate, snapshot, replace and delete lines), with
nothing changed in the cluster or in AWS. Live: the join taints go, a
warning taint appears, a fake kubelet on worker 1 gets the critical taint
and the breaker hold, and after approval worker 1 is quarantined,
snapshotted, detached and deleted; the control plane can no longer reach
it; the replacement joins and is cleared; terminate removes the old
instance and keeps the snapshots. Both modes check that the admin cannot
set a trust taint.

The evidence snapshots are not deleted by `terraform destroy`; the script
prints the command to delete them.

## Live run notes

Dry run, first tries (2026-11-19, ami-034d8e94160b0fecb). Each found a
bug, fixed before the next try:

- The control plane node was handled as a worker: it also has an aws:///
  provider ID, and kubeadm sets its role label with an empty value, which
  the first code read as "no label". Live, it would have been tainted and
  counted for the circuit breaker. The controller now tests that the label
  is present (TestControlPlaneNotManaged).
- The check could not read the node list: SSM returns at most 24000
  characters of output and `kubectl get nodes -o json` is longer. The check
  now asks for one short line per node and filters the controller log on
  the host.
- After a restart the dry-run controller did not log its plans again (it
  had saved them), so the log of the new run was incomplete. Plans are now
  logged again after every restart.
- The circuit breaker did not hold the critical node: the Node objects of
  every worker replace-workers.sh had terminated were still in the API
  (kubeadm has no cloud controller to remove them), so 1 critical node of
  2 looked like 1 of 10. The breaker now counts only workers with a fresh
  signed state (TestBreakerCountsAttestedWorkersOnly), and
  replace-workers.sh deletes the Node objects of terminated workers.

Dry run, fifth try (2026-11-20 00:10 IST, fresh workers): check-controller.sh
fails=0. Healthy workers: "would trust taints removed" while the nodes kept
their join taint; unknown binary on worker 2 (warning 90): "would trust
taints warning:PreferNoSchedule"; fake kubelet on worker 1 (critical):
"would trust taints critical:NoExecute", "would cordon", the secrets to
rotate (calico and kube-proxy service accounts, calico node certificates),
and "would hold isolation: circuit breaker open (1 critical of 2
workers)"; after approve: would isolate, snapshot, replace and release.
Nothing changed: worker 1 kept its security group, no ACL deny, no
snapshot, still in the group, join taint still on. The cluster admin's
attempt to add a trust taint was denied by the nodetrust-taints policy.

Live run, first try (2026-11-20 00:20 IST): the join taints came off, the
warning taint went on, the critical taint and cordon followed 11 s after
the fake kubelet ran, the circuit breaker held with no AWS change, and
after approval the isolation (quarantine group and ACL denies) was done.
The snapshot step then failed on every retry: DescribeSnapshots takes
Owner.N in the EC2 query API ("OwnerId" is the name in the CLI and the
response). The fake EC2 in the unit test had the same wrong name, so the
test could not catch it; both are fixed. The redeployed controller resumed
the half-done containment from its saved phase.
After the fix the restarted controller finished worker 1 in its first
round: snapshot snap-0f2eca0ef3422bc53, detached from the group, Node
object deleted, all within half a second (the "7m15s" counts from the
finding and includes the minutes the snapshot step was failing).

Capacity: the account's vCPU limit is 8 (control plane, verifier and two
m6i.large workers use all 8). While a quarantined worker keeps running for
forensics, the group cannot launch its replacement ("You have requested
more vCPU capacity than your current vCPU limit of 8"), so containment on
this account means running one worker short until the operator terminates
the quarantined instance. check-controller.sh therefore terminates it
(after checking the snapshots) before waiting for the replacement. A real
fleet needs headroom of one node per expected quarantine, or a quota
increase.
`nodetrust-controller terminate -instance i-0d23c46d1c9be2c45 -yes` then
terminated the first quarantined worker through the controller's role (the
IAM policy allows TerminateInstances only on instances tagged as
contained) and kept snap-0f2eca0ef3422bc53.

### Result: Phase 5 gate (2026-11-20 01:09 IST, ami-034d8e94160b0fecb)

check-controller.sh, live, fresh workers: fails=0.

- both workers lost the unattested join taint once verified; an unknown
  binary on worker 2 (warning 90) gave it warning:PreferNoSchedule
- a fake kubelet run on worker 1: critical:NoExecute and cordon 10 s
  later (verifier challenge plus one controller round); the circuit breaker
  held (1 critical of 2 workers) with no AWS change
- after `approve`: worker 1's ENI in the quarantine group only, ACL denies
  in and out for its IP, snapshot snap-000ce2af754f6c035, detached from
  the group, Node object deleted. Isolate to release took about 1 s (the
  "done in 31 s" times count from the finding, including the wait for
  approval)
- the control plane could reach worker 1's kubelet port before and not
  after
- `terminate` removed worker 1 and kept the snapshot; the group's
  replacement joined, was verified healthy at 100 and lost its join taint
- the cluster admin could not add a trust taint (nodetrust-taints policy)

With the dry run (fifth try, fails=0) this passes the Phase 5 gate:
dry-run logs match the expected actions for every scenario, and one live
quarantine succeeded end to end.
