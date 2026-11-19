# Phase 1

Step 1.1 (platform probe): passed on 2026-11-15, 15 of 15 checks plus the EK
match, on base AMI ami-0d9cf6e2a0d483386 in ap-south-1.

Step 1.2 (golden worker AMI): passed on 2026-11-15, 45 of 45 golden checks plus
the EK match, on ami-0b3225d5d09f2f390 (nodetrust-worker-k8s-v1.35-202611150847):
kernel 7.0.0-1017-aws, Kubernetes 1.35.10, containerd 2.2.1, runc 1.3.4. The IMA
policy loaded by path, so the kernel measured the policy file itself.

Step 1.4 (module lock): passed on 2026-11-15, 49 of 49 golden checks plus the
EK match, on ami-0ecbc5bf91f8cfc07 (nodetrust-worker-k8s-v1.35-202611151015).
Earlier golden AMIs without the lock were deregistered.

# Step 1.1: platform probe

Before building the golden AMI and the cluster, this step checks on one real
NitroTPM instance that every platform assumption in the blueprint holds.

## What it checks

PASS/FAIL (the design depends on these):

- kernel 6.3 or newer (needed for vm.memfd_noexec)
- /dev/tpmrm0 present and the SHA-256 PCR bank allocated
- Secure Boot enabled, kernel lockdown active
- IMA on with ima-ng and SHA-256, and a software replay of the IMA log equals
  the quoted PCR 10 (the core of the verifier)
- vm.memfd_noexec, kernel.modules_disabled and kernel.kexec_load_disabled exist
- the RSA EK created on the node equals the EK from GetInstanceTpmEkPub

INFO (recorded for step 1.2 and Phase 4): kernel config for IMA and lockdown,
which PCR banks exist, replay results for the other banks, and a snapshot of
the boot PCRs.

## Prerequisites

AWS CLI v2 configured with a region, curl, gzip, and permission to use EC2,
SSM, and IAM (create a role and an instance profile). The probe uses the
default VPC.

## Run

```
cd infra/phase1
export AWS_REGION=ap-south-1                      # your region
aws sts get-caller-identity                       # must print your account

AMI=$(./01-register-base-ami.sh) && echo "AMI=$AMI"   # about 5-10 minutes
ID=$(./02-launch-probe.sh "$AMI") && echo "ID=$ID"
./03-run-probe.sh "$ID"                           # waits for the reboot, then probes
./99-cleanup-probe.sh "$ID"                       # keeps the base AMI for step 1.2
```

Each script prints only its result (an AMI or instance ID) on stdout and
its progress on stderr, so do not pipe it through tail: a pipe hides a
failed exit status. Every script checks AWS credentials before doing
anything.

Canonical's blob.bin downloaded on 2026-11-15 had sha256
2361a3dda3d3188c0f9d6d2106a40cc16f22e2c73d5338ddce048e5d0999f34d.

03-run-probe.sh saves everything to probe-<instance-id>.txt. Send that file
back: its INFO lines decide details of the golden AMI (for example, whether the
kernel lets the IMA policy be replaced after boot).

Terminate the probe instance when you are done. The base AMI and its snapshot
cost a little for storage until you deregister them.

## Files

- 01-register-base-ami.sh: copies the Ubuntu 24.04 root snapshot and registers
  it with UEFI boot, NitroTPM v2.0, IMDSv2 only, and Canonical's Secure Boot
  variable store
- 02-launch-probe.sh: launches one instance with no SSH key and no inbound
  rules, reachable only through SSM
- probe-userdata.sh.tmpl: first-boot script; installs tpm2-tools, turns IMA on
  with the built-in tcb policy, reboots once
- probe.sh: the checks, run on the instance as root
- ima_replay.py: replays the binary IMA log against a PCR bank;
  test_ima_replay.py holds its unit tests
- 03-run-probe.sh: runs the probe through SSM and compares EKs
- 99-cleanup-probe.sh: terminates the probe instance

# Step 1.2: golden worker AMI

ami/build-golden-ami.sh launches a builder from the base AMI. User data runs
ami/provision.sh, which:

- patches everything, removes unattended-upgrades, masks the apt timers and
  holds snap refreshes (workers are immutable)
- installs containerd, runc and kubelet/kubeadm/kubectl from pkgs.k8s.io
  (K8S_MINOR, default v1.35) and holds them
- adds ima_policy=tcb ima_template=ima-ng ima_hash=sha256 lockdown=integrity
  to the kernel command line, and a oneshot unit that loads
  /etc/nodetrust/ima-policy early in boot, which uses up the one policy write
  the kernel allows per boot
- sets vm.memfd_noexec=2, kexec_load_disabled, unprivileged_bpf_disabled,
  bpf_jit_harden, and mounts /tmp, /var/tmp and /dev/shm noexec
- masks SSH and removes compilers

Then it powers off. The script snapshots the root disk, registers it with the
same UEFI, NitroTPM, IMDSv2 and Secure Boot settings as the base AMI (the
Secure Boot blob is pinned by its sha256 in lib.sh), and terminates the builder.

kernel.modules_disabled is set in step 1.3, after the module list a running
worker needs is captured.

## Run

```
cd infra/phase1
export AWS_REGION=ap-south-1
GOLDEN=$(./ami/build-golden-ami.sh ami-0d9cf6e2a0d483386) && echo "GOLDEN=$GOLDEN"   # 15-25 minutes

ID=$(PROBE_MODE=golden ./02-launch-probe.sh "$GOLDEN") && echo "ID=$ID"
PROBE_MODE=golden ./03-run-probe.sh "$ID"
./99-cleanup-probe.sh "$ID"
```

If the build fails, the builder is left running and its console output is
printed. Inspect it with aws ssm start-session --target <builder-id>, then
terminate it by hand.

## Golden checks (probe.sh --golden), in addition to the step 1.1 checks

- the IMA policy file is gone (the one write is used) and the policy is in the log
- a file root writes and reads on ext4 is logged with sha256(content): the
  basis of the IMA canary
- a root read on tmpfs is not logged: the tcb policy was replaced
- reads of /boot and the EFI partition are logged: the forced-read sweep works
- every sysctl from blueprint 6.5 has its value
- memfd_create(MFD_EXEC) and exec of a memfd are refused
- /tmp, /var/tmp, /dev/shm are noexec, and a binary in /dev/shm cannot run,
  directly or through ld.so
- SSH off and masked, no unattended-upgrades, apt timers masked, snap
  refreshes held, no compilers, Kubernetes packages held, SystemdCgroup on
- runc still starts a container with vm.memfd_noexec=2

# Step 1.4: module lock and final Phase 1 gate

The first cluster run (2026-11-15) captured the 74 modules a working worker
loads. The golden AMI now preloads the 40 networking ones among them, plus
nft_ct for the Phase 5 peer-side deny, through /etc/modules-load.d. A late
oneshot unit, nodetrust-modules-lock.service, then sets
kernel.modules_disabled=1 after udev, containerd and kubelet have started.
Hardware modules still load through udev at boot, before the lock.

probe.sh --golden adds: the preload ran cleanly, the lock unit ran,
kernel.modules_disabled = 1, and a fresh modprobe is refused.

## Run

```
cd infra/phase1
GOLDEN=$(./ami/build-golden-ami.sh ami-0d9cf6e2a0d483386) && echo "GOLDEN=$GOLDEN"
ID=$(PROBE_MODE=golden ./02-launch-probe.sh "$GOLDEN") && echo "ID=$ID"
PROBE_MODE=golden ./03-run-probe.sh "$ID"
./99-cleanup-probe.sh "$ID"

cd ../cluster
echo "worker_ami = \"$GOLDEN\"" > terraform.tfvars
terraform apply
./check-cluster.sh
terraform destroy
```

## Step 1.5: one kernel in the image (found in step 2.1)

The manifest of ami-0ecbc5bf91f8cfc07 listed two kernels,
/boot/vmlinuz-7.0.0-1014-aws (the one the builder booted) and 7.0.0-1017-aws
(installed by full-upgrade). A signed manifest would vouch for the old one
too. provision.sh now purges every kernel except the newest (image, modules,
headers, tools) before update-grub, and build-info records kernel=<version>.
The golden probe gains two checks: single-kernel (only the running kernel is
in /boot) and grub-single-kernel (every GRUB entry boots it).
