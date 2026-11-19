# Phase 1, step 1.3: cluster

Terraform for the nodetrust environment in one AZ:

- VPC with a public subnet (NAT gateway only) and private subnets for the
  control plane, the verifier and the workers
- worker subnet with its own network ACL: allow-all at rule 1000, rules below
  it reserved for the controller's quarantine denies (Phase 5)
- security groups with no inbound from the internet; workers accept only the
  control plane, other workers (Calico VXLAN, Typha) and, on the agent port,
  the verifier
- IAM: every host gets SSM only; the verifier may also read EKs and describe
  instances; workers get nothing else
- control plane: one instance from the golden AMI, kubeadm init, Calico
  v3.32.4 (tigera operator, VXLAN, iptables dataplane, BGP disabled).
  v3.30.0 was used first: it predates Kubernetes 1.35 and left the operator
  stuck Degraded. BGP must be off with VXLAN, or calico-node waits for BGP
  peers on a port the security groups do not open
- verifier host: idle until Phase 4
- workers: launch template (IMDSv2 only, hop limit 1, ENI tracked-TCP timeout
  60 s) and an Auto Scaling group with MaxInstanceLifetime; workers join with
  the trust.k8s-attest.io/unattested taint and an aws:/// providerID

The cluster is created and destroyed per work session.

## Prerequisites

- Terraform 1.6+ (or OpenTofu), AWS CLI v2
- optional: the Session Manager plugin, for interactive shells
  (aws ssm start-session)

Terraform may not read `aws login` sessions directly, so export them first:

```
eval "$(aws configure export-credentials --format env)"
export AWS_REGION=ap-south-1
```

## Run

```
cd infra/cluster
echo 'worker_ami = "ami-0b3225d5d09f2f390"' > terraform.tfvars
terraform init
terraform apply          # about 5 minutes; the cluster itself needs about 10 more
./check-cluster.sh       # waits for the cluster, then checks it
```

check-cluster.sh checks the AWS-side settings, runs the in-cluster checks on
the control plane (nodes, taints, providerIDs, Calico, cross-node traffic, DNS,
a NetworkPolicy deny-then-allow test), and checks that module loading is
locked on every worker. It writes cluster-check-<time>.txt and, per worker,
modules-<instance>.txt. Send the check file back.

To use kubectl on the control plane:

```
aws ssm start-session --target "$(terraform output -raw controlplane_id)"
sudo -i
kubectl --kubeconfig /etc/kubernetes/admin.conf get nodes
```

End of session:

```
terraform destroy
```

The NAT gateway and four instances bill per hour while the cluster exists.

## Phase 1 simplifications (replaced later)

- One bootstrap token with no expiry, shared by all workers through the launch
  template, and the cluster CA key in the control plane's user data and in
  Terraform state. Blueprint 10.4 replaces this with per-node tokens issued by
  the verifier (Phase 4).
- No drain hook for instance refresh yet (Phase 5).

## Result (2026-11-15)

Verified on a fresh cluster built from this template (golden AMI
ami-0ecbc5bf91f8cfc07, K8s v1.35.10, Calico v3.32.4): check-cluster.sh gave
remote pass=12 fail=0 and local pass=11 fail=0. Both workers had
kernel.modules_disabled = 1 with 75 modules loaded, the unattested taint and
the aws:///az/iid providerID. Cross-node pod traffic, cluster DNS and the
NetworkPolicy deny/allow test all passed. Destroyed cleanly (50 resources).

The earlier Calico failure was BGP: calico-node waited for BIRD peers on TCP
179. Setting bgp: Disabled in the Installation fixed it; it was confirmed by a
live patch first and then on the fresh cluster.
