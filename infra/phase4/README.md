# Phase 4: verifier service

## Step 4.1: boot event log checks

The quote proves PCRs 0-10. PCR 10 is checked through the IMA log (Phase 3).
PCRs 0-9 are set by firmware, shim and GRUB before Linux runs, and they can
not be pinned as fixed values on this boot chain:

- PCR 1 holds the boot variables, and Boot0001 is named after the instance's
  own root volume ("UEFI Amazon Elastic Block Store vol0af9… 1"), so it is
  different on every instance.
- GRUB writes grubenv on every boot (recordfail, initrdfail) and measures it
  into PCR 9.

So the verifier reads the firmware's event log (binary_bios_measurements),
replays it to the quoted PCRs 0-9, and then checks every event
(pkg/bootpolicy):

| PCR | check |
|-----|-------|
| 0 | firmware value in a reviewed allow-list |
| 1 | only BootOrder and Boot#### variables; one names this instance's root volume (from EC2) |
| 2, 3, 6 | separator only |
| 4 | exactly three EFI applications, in order: shim (BOOTX64.EFI or shimx64.efi), GRUB (grubx64.efi), then the kernel the command line names; each by its Authenticode hash in the signed manifest. Other signed images in the manifest (MokManager, fallback, an old kernel) do not pass |
| 5 | GPT of the AMI's disk, and the two exit-boot-services actions |
| 7 | SecureBoot = 1; PK, KEK, db, dbx, and the db, SbatLevel and MokListRT authorities equal the reference |
| 8 | the kernel command line equals the AMI's and has ima_policy=tcb, ima_template=ima-ng, ima_hash=sha256, lockdown=integrity |
| 9 | every file GRUB loaded is in the signed manifest with that sha256 (grubenv excepted); the initrd the kernel received is one of them; the load options the kernel received are the expected command line |

Events whose digest is the hash of their own data (variables, GRUB commands,
actions, the GPT) are checked for that too, so the text the checks read is
the text that was measured. Facts confirmed on the real log of
ami-07deef95f949d1d5d:

- PCR 8: digest = sha256 of the command without "grub_cmd: " or
  "kernel_cmdline: " and without the NUL (all 72 events)
- PCR 9: the kernel's EFI stub tags its load options as
  sha256(UTF-16LE("BOOT_IMAGE=" + command line)), and the initrd as the
  sha256 of /boot/microcode.cpio: Ubuntu's cloud image boots without an
  initrd, and GRUB gives the kernel only the microcode
- PCR 4: the Authenticode hashes of shim 15.8, GRUB 2.12 and the
  7.0.0-1017-aws kernel, computed by manifest.py from the Ubuntu archive
  packages (byte-identical to the AMI's files), equal the logged digests

The Authenticode hashes are new in the manifest (manifest.py/2,
`authenticode_sha256` on PE files under /boot), and the agent now sends the
event log with each quote, so the golden AMI is rebuilt for this step.

Tests: pkg/bootpolicy runs the real log through every check, then breaks it
in ways an attacker controlling the boot could (another kernel command line
measured honestly, text that does not match its digest, other load options,
Secure Boot off, an extra EFI application, a log that does not replay) and
with policy and manifest changes; each fails on the expected check. The
simulator test checks that the verifier rejects an event log that does not
replay to the quote.

### Run

```
make test
cd infra/phase1
GOLDEN=$(./ami/build-golden-ami.sh ami-0d9cf6e2a0d483386) && echo "GOLDEN=$GOLDEN"
ID=$(PROBE_MODE=golden ./02-launch-probe.sh "$GOLDEN") && echo "ID=$ID"
PROBE_MODE=golden ./03-run-probe.sh "$ID"
./99-cleanup-probe.sh "$ID"
cd ../phase2
./build-manifest.sh "$GOLDEN" && ./sign-manifest.sh "$GOLDEN" && ./log-rekor.sh "$GOLDEN"
cd ../cluster
echo "worker_ami = \"$GOLDEN\"" > terraform.tfvars
terraform apply && ./check-cluster.sh
cd ../phase3 && ./attest-cluster.sh
cd ../phase4 && ./check-boot.sh      # first run: writes a boot policy for review and stops
# review check-boot-*/boot-policy.json, copy it to infra/phase4/boot-policy.json
./check-boot.sh                      # second run: checks both workers
cd ../cluster && terraform destroy
```

check-boot.sh writes the first policy from worker 1's log, so the second run
on worker 1 only shows the policy is self-consistent; worker 2 is the real
test (same AMI, different instance and volume). The negative check gives
worker 1's log with worker 2's root volume and must fail on PCR 1.

### Result (2026-11-18, ami-02dc3031448c845a0, ap-south-1c, two workers)

- probe 57/57; manifest.py/2 with Authenticode hashes for shim, GRUB, the
  kernel and the other EFI images; signed and logged (Rekor 3967225701)
- attest-cluster.sh: both workers enrolled, two TLS-bound quotes each, and
  each quote's boot event log (118 events) replayed to the quoted PCRs 0-9
- the boot policy written from worker 1 matched every value checked by
  hand on the previous AMI (firmware PCR 0, GPT, command line, the eight
  Secure Boot digests)
- check-boot.sh: 31 checks pass on each worker (root volumes
  vol-084c34c32fbb06e85 and vol-01f075fbaae443af4); worker 1's log given
  with worker 2's root volume is rejected on PCR 1

After the run the PCR 4 check was tightened from "any EFI image in the
manifest" to the shim, GRUB, kernel order (efi_boot_chain in the policy),
with tests for MokManager in GRUB's place, shim and GRUB swapped, and a
signed kernel the command line does not name.

## Step 4.2: verifier service

`verifier serve` runs on the verifier host as nodetrust-verifier.service.
Every round (30 s) it:

1. lists running instances tagged role=worker, project=nodetrust with
   ec2:DescribeInstances (instance ID, private IP, AMI, root volume all come
   from EC2, not from the node)
2. refuses any instance whose AMI is not on the allow-list, or whose AMI's
   manifest bundle in S3 does not verify (signature with the pinned key,
   AMI binding, manifest hashes, Rekor entry with the pinned log key)
3. enrolls new instances: EK from ec2:GetInstanceTpmEkPub, then credential
   activation with the agent over mTLS; the enrollment is kept in
   /var/lib/nodetrust-verifier/enrolled/ across restarts and dropped when
   the instance leaves the inventory
4. takes a TLS-bound quote from every enrolled node and judges it: IMA
   measurements against the AMI's manifest and the runtime policy, boot
   event log against the boot policy (step 4.1)
5. writes /var/lib/nodetrust-verifier/status.json: per node one of
   trusted, untrusted (a verified quote shows something wrong),
   bad-evidence (the quote does not verify), unreachable, enroll-failed,
   refused

The AWS calls use the instance role (IMDSv2) through a small stdlib client
(pkg/provider/aws: SigV4 checked against the AWS documentation examples).
The verifier role gets s3:GetObject on manifests/* and signed/* of the
manifest bucket, nothing else new. The service runs as a dynamic user with
no capabilities; the client key is passed as a systemd credential.

The runtime policy no longer has the /root/nt/ and /root/nt-ima/ rules of
the step 2.4 harness (a file there would have passed unchecked). They moved
to infra/phase2/harness-policy.json, which check-node.sh and recheck.sh merge
in for their own runs.

Tests: SigV4 and the EC2/S3/IMDS client against fake servers (signatures
recomputed on the server side, the EndorsementProvider conformance suite);
Judge on the real NitroTPM boot log (trusted, unknown binary, replaced
kubelet, log of another instance, no boot log, kernel not in the manifest);
the daemon on the TPM simulator (allowed AMI trusted, stock AMI and
unverified manifest refused without an EK lookup, wrong EK fails enrollment,
an unknown binary makes the node untrusted, a restart keeps the enrollment,
a wrong stored AK gives bad-evidence, a terminated instance is forgotten).

### Run

```
cd infra/cluster
echo "manifest_bucket = \"$(terraform -chdir=../trust output -raw manifest_bucket)\"" >> terraform.tfvars
terraform apply && ./check-cluster.sh
cd ../phase4 && ./deploy-verifier.sh
./check-verifier.sh
cd ../cluster && terraform destroy
```

check-verifier.sh: both workers trusted; a stock Ubuntu instance tagged
role=worker is refused and never enrolled; a copy of /usr/bin/true run from
/root on worker 1 makes worker 1 untrusted (the file is named) while worker
2 stays trusted; a service restart enrolls nothing again.

### Result, first cluster run (2026-11-18, ami-02dc3031448c845a0)

- deploy-verifier.sh: the service enrolled both workers on its own (EK from
  EC2, credential activation over mTLS) and judged them trusted in its first
  round (about 2,240 manifest matches, 14-16 changed and 416-453 runtime
  files allowed by the policy, boot pass); later rounds take 0.1 s
- check-verifier.sh: a stock Ubuntu spot instance tagged role=worker was
  refused (AMI not on the allow-list) and never enrolled; /root/nt-unknown-
  binary run on worker 1 made it untrusted; a service restart enrolled
  nothing again
- the run also found a real problem: worker 2 turned untrusted on its own
  with 18 unknown files under /var/cache/fwupd and /var/lib/fwupd. The
  fwupd-refresh timer had downloaded firmware metadata from LVFS and fwupd
  (root) read it back. That data comes from the internet and is in no
  manifest, so the verifier was right to flag it. The fix is in the image,
  not the policy: provision.sh now masks fwupd, its refresh timer and the
  motd-news timer (which does the same with the motd), and the probe checks
  that they are masked and lists every timer on the image (59 checks)

### Result, second cluster run (2026-11-18, ami-0b554e8ddf441beef, fwupd and motd-news masked)

- probe 59/59; manifest signed and logged (Rekor 3970524255); the boot
  policy entry for the new AMI equals the old one (GPT, command line), and
  Secure Boot and firmware values are unchanged
- check-boot.sh: 31 checks pass on both workers; the other-volume test fails
  on PCR 1 as it should
- deploy-verifier.sh with only the new AMI allowed: both workers enrolled and
  trusted in the first round (2,253 matches, 14-15 changed, 414-453 runtime)
- check-verifier.sh: 0 fails. Stock Ubuntu instance refused and not
  enrolled; unknown binary on worker 1 detected (worker 1 untrusted, worker 2
  still trusted, so no fwupd-style noise this time); restart kept both
  enrollments

## Step 4.3: trust levels over time

Each round's verdict is folded into a per-node track (pkg/verifier/track.go,
saved in /var/lib/nodetrust-verifier/track/<id>.json, last 50 events). The
node's level is what Phase 5 acts on:

| level | when |
|-------|------|
| trusted | verified evidence and score 80 or more |
| suspect | evidence verifies, but score below 80: a recent reboot (-30), TPM restart (-10) or missed quotes (-10 each); every clean round gives +5 back |
| untrusted | compromised: a verified quote showed something wrong, a quote did not verify, or a TPM counter went backwards. Sticky: it stays until the node is replaced |

The TPM's resetCount, restartCount and clock are signed in every quote (the
AK is in the endorsement hierarchy, so they are not obfuscated). resetCount
going up is a reboot: the new boot is checked in full (event log, IMA log)
like any other. Any counter going back is treated as compromise.

The compromise rule is sticky on purpose: a reboot starts a clean IMA log,
so without it an attacker could reboot the evidence away.

status.json now shows per node: level, score, compromised (and why),
reboots, consecutive misses and the last 8 events.

Tests: the scoring rules in table tests (steady, reboot and recovery, stale
node, sticky compromise across a reboot, counter rollbacks, TPM restart,
firmware change); the simulator test checks levels, the saved track across
a verifier restart, and that a terminated node's track is removed.

### Run

On a fresh cluster (check-verifier.sh leaves worker 1 compromised, so run
this instead of it, or on a new cluster):

```
cd infra/cluster && terraform apply && ./check-cluster.sh
cd ../phase4 && ALLOWED_AMIS=<golden AMI> ./deploy-verifier.sh
./check-tracking.sh
cd ../cluster && terraform destroy
```

### Result, first 4.3 run (2026-11-18, ami-0b554e8ddf441beef)

- NitroTPM raises resetCount on a reboot: the verifier logged the reboot
  and checked the new boot in full
- that check failed on PCR 7: dbx differed from the reference. diag-dbx.sh
  showed why: secureboot-db.service runs sbkeysync at every boot, and on a
  worker's first boot it inserted Ubuntu's dbx update
  (/usr/share/secureboot/updates/dbx/dbxupdate_x64.bin, 17,836 bytes) into
  the empty dbx of Canonical's variable store. The reference was taken from
  first boots, so every worker's second boot looked wrong.
- the verifier handled it as designed (untrusted, sticky, kept across a
  verifier restart), and a worker compromised by an unknown binary stayed
  untrusted
- fix, in the image: build-golden-ami.sh now registers the AMI with the
  builder's own UEFI variable store (read with ec2:GetInstanceUefiData after
  the build), which already holds the dbx update, so workers boot with the
  revocations from the start; the probe checks that sbkeysync inserted
  nothing on the golden instance (dbx-in-image) and prints the dbx size.
  Masking secureboot-db would also have made PCR 7 stable, but by dropping
  the revocations, so it was not done.

Second run, with ami-08349e39ae54ff662 (builder UEFI store):

- the dbx fix worked: probe 60/60 with dbx-in-image PASS (dbx 17,840 bytes),
  the new boot policy differed from the old one only in dbx, check-boot
  passed 31 checks on each worker, and PCR 1 still names each worker's own
  root volume (no builder boot entries came over)
- both workers were untrusted from their first quote with one unknown file,
  /etc/udev/rules.d/90-cloud-init-hook-hotplug.rules. The rebuild pulled
  cloud-init 26.2, whose EC2 datasource allows network hotplug by default;
  its install_hotplug module writes that udev rule at a worker's first boot
  (cloud-init clean removed it from the image, so it is in no manifest), and
  udev reads it as root on every boot after, so IMA measures it
- fix, in the image: provision.sh adds
  /etc/cloud/cloud.cfg.d/99-nodetrust-no-hotplug.cfg (network updates only on
  boot-new-instance) and removes any leftover rule; the probe checks that no
  hook is installed and hotplug is not enabled (no-hotplug-hook). Workers
  never get network cards added while running, so nothing is lost.
- check-tracking.sh now retries status reads (a short SSM endpoint outage on
  the laptop crashed it) and stops after step 1 if the workers are not
  trusted, listing the unknown files

Third run, with ami-0db8162878b3b3af2 (hotplug off): probe 61/61
(no-hotplug-hook PASS), check-boot 31 checks per worker, both workers trusted
from the first round, and check-tracking.sh fails=0: reboot detected (score
100 -> 70, suspect), back to trusted after clean rounds, the compromised
worker stayed untrusted through a clean post-reboot quote, and the
compromise, reboot count and levels survived a verifier restart.

## Step 4.4: trust engine (blueprint Section 7)

A review against Blueprint v2 after step 4.3 found that the verifier gave a
binary verdict (any unknown or mismatched file made a node untrusted), which
is the baseline of blueprint 12.4, not the framework. Step 4.4 replaces it
with the blueprint's trust engine. pkg/trust is pure and cloud-neutral;
pkg/verifier keeps the per-node state.

Each verified quote is split into:

- critical findings (7.2), which skip the score and go to the critical path:
  kubelet, containerd, containerd-shim-runc-v2, runc, the agent or Falco not
  matching (matched by file name, so a changed copy run from another
  directory counts too); a file in /boot or the EFI partition not in the
  manifest; a kernel module not in the reference; /etc/ld.so.preload; the
  IMA policy changed; the boot policy failing (boot PCRs, Secure Boot); a
  quote that does not verify; evidence missing; a TPM counter going back;
  a score below 50
- files against the score (7.3): five components with weights and
  tolerances as in the blueprint (system binaries 30/3, Kubernetes config
  25/2, system config 20/4, runtime config 15/1, security policy 10/2),
  S = sum of w * max(0, 1 - m/t). Tiers: above 90 healthy, 75-90 warning,
  50 to below 75 degraded, below 50 untrusted (handled as critical)

Drift (7.4): every fall of the score is labelled sudden (15 or more),
isolated (no other drop in 30 cycles) or gradual (3 or more drops in 30
cycles, together at least 10). A worse tier applies at once; a better one
only after it holds for 3 cycles (8.2).

Unit tests check every scenario of 12.1 that has an expected score: A1, A2,
A3, A7, A13 critical; A8 and A9 90 (warning, isolated); A10 72.5 (degraded,
sudden); A11 80 (warning, gradual on the third edit).

Where the code differs from the blueprint text, and why:

- Missing evidence. The blueprint says two failed cycles in a row are
  critical (6.3), but also that a node reboot must give no critical finding
  (12.2), and a reboot always costs a few cycles. Here one failed cycle is
  retried at once (2 s later), two failed cycles make the node unattested
  (the controller puts the unattested taint back, as 6.2 step 6 says for a
  reboot), and a node with no valid quote for 2 minutes is critical
  (evidence-missing). Nothing is lost in the wait: the IMA log only grows
  until a reboot, so the next quote still shows everything done while the
  agent was silent, and a reboot is checked in full. A quote that does not
  verify is still critical at once. 12.3's "block one worker for 3 minutes"
  still gives the critical path.
- Outage (8.4). If every enrolled node fails in the same round, the round is
  recorded as an outage and nothing is counted. The blueprint puts this in
  the controller; it is done in the verifier as well, so the verifier never
  produces a missing-evidence finding for the whole fleet.
- Sticky across reboots. The blueprint keeps mismatches for the whole boot
  and lets a tier improve only through a corrected manifest. A reboot
  starts a clean IMA log, so the verifier keeps mismatched files across
  reboots too; only a corrected manifest (the file now matches) clears one.
- A drop that fits none of the three drift labels (a second small drop in
  the window, or three that add up to less than 10) is reported as
  "unclassified"; the blueprint does not name this case.
- ima-ng does not record whether a file was executed or read, so an unknown
  file outside the config paths counts as an unknown executable (system
  binaries).
- The reboot and missed-quote penalties of step 4.3 are gone; a reboot is
  only an event, as in the blueprint.

Known gap, for step 4.6: the runtime policy still allows /etc/kubernetes/,
/var/lib/kubelet/, /etc/cni/net.d/ and /opt/cni/bin/ wholesale, so changes
there are not scored yet. Join-time hashes and fleet consensus (10.4) close
this.

Live check: check-scoring.sh (replaces check-tracking.sh): outage with no
action, A8, a runtime-config change (sudden), reboot without a critical
finding and with the mismatch kept, a critical binary, the agent stopped
(unattested, then evidence-missing), and a verifier restart.

Result (2026-11-18, ami-0db8162878b3b3af2, interval 30 s): check-scoring.sh
fails=0.

- outage: with the verifier's connections to the agents dropped for 90 s,
  both nodes showed state "outage"; afterwards both were verified, healthy,
  100, never unattested or critical
- A8 (/usr/bin/yes changed and run): 90, warning, drift isolated
- containerd config changed and read: 85, warning, drift sudden
- reboot of worker 1: failed cycles, unattested for a moment, then a
  verified quote with the reboot event; no critical finding, and the
  /usr/bin/yes mismatch stayed (90, warning) although the new IMA log was
  clean
- a changed copy of kubelet run from /usr/local/bin: critical
  (critical-binary, matched by name), score unchanged at 85
- agent stopped: unattested after two failed cycles, critical
  (evidence-missing) after 2 minutes, still critical once the agent was back
- verifier restart: scores, files and findings kept on both workers

## Step 4.5: what each challenge carries (blueprint 6.2, 10.2, 10.3, 10.5)

Protocol v2 (pkg/protocol). Before quoting, the agent:

- writes the challenge's canary (32 random bytes) to
  /var/lib/nodetrust/canary and reads it back. The verifier expects an IMA
  entry for that file with sha256(canary) in the quoted log; without it IMA
  has stopped recording, which is critical (ima-canary)
- opens every file of the sweep set the verifier names (forced-read sweep).
  IMA measures at open and only hashes a file that changed, so this is
  cheap. The critical set (kubelet, containerd, the shim, runc, the agent,
  Falco, sshd, /usr/local/bin, /etc/nodetrust, /boot with the EFI
  partition) is swept in every challenge; the full set (/usr/bin, /usr/sbin,
  /usr/local, /usr/libexec, /etc, /opt/cni/bin, the kubelet config, /boot
  and the parts of /usr/lib with executables and configs) in the first
  challenge of a boot and every 10th. Kernel modules and firmware are left
  out: the kernel measures them when it loads them, and modules are locked
  after boot. A binary replaced but never run (A13) is caught at the next
  sweep
- lists the mounts of every mount namespace (from /proc/<pid>/ns/mnt and
  mountinfo; for a container namespace only its overlay mounts). The
  verifier finds: any overlay whose directories are outside containerd's
  snapshotter tree (A15), and, outside container namespaces, any mount at,
  under or above a watched path that does not show the host's own files
  there (same device and subtree as the host's /, /boot or /boot/efi);
  systemd's read-only views pass this rule, a tmpfs or another directory
  bound over /usr/bin does not. The audit is a snapshot and is as honest as
  the agent; the agent's binary is in the critical set

The IMA log is incremental: the verifier keeps where its replay stands
(offset, entries, PCR 10) and asks only for what is new; a new boot (another
TPM resetCount) gets the whole log and the boot event log again. Between
those, the boot PCRs must stay the values checked against the event log at
the start of the boot.

Intervals (6.2): 60 s for a healthy node, 30 s at warning, 15 s when
degraded, unattested, critical, not yet verified, or changed (reboot or
score drop) in the last 10 minutes. Hints (10.5): the verifier keeps a long
request open to each agent, which answers when IMA's measurement count goes
past what the verifier last read; the verifier then challenges at once (at
most every 5 s). Hints are advisory: a missing hint changes nothing.

Outage (8.4) is now decided per failed cycle: it counts only if some other
enrolled node's agent still accepts a TCP connection.

The agent gets one capability, CAP_SYS_PTRACE: reading another process's
ns/mnt link and mountinfo needs it when that process has capabilities the
agent lacks. The probe checks the bounding and effective sets. Its only
writable path is its StateDirectory (/var/lib/nodetrust), for the canary.

Live check: check-probes.sh (canary, sweep, mount audit and incremental log
on clean nodes, base interval; hint latency for an unknown binary; A13; A15;
a blocked canary). check-scoring.sh still applies.

First live run of 4.5 (ami-034d8e94160b0fecb) found two false positives,
both fixed in the verifier (no image change):

- mount-bind /usr/lib/modules in the namespaces of systemd-resolved,
  systemd-networkd, the agent and others: systemd's ProtectKernelModules
  hides the module directories with its "inaccessible" node (a bind from
  /run/systemd/inaccessible/dir on the host's /run tmpfs). That node is now
  allowed at /usr/lib/modules and /lib/modules only; anywhere else, or from
  another tmpfs, it is still critical
- two unknown files from the full sweep,
  /usr/lib/python3/dist-packages/setuptools/command/launcher_manifest.xml
  and .../script_(dev).tmpl: the real names have a space ("launcher
  manifest.xml"), and IMA logs whitespace in a name as '_'. The manifest
  index now also answers for the underscored name (the hash must still
  match; a real file of that name wins)

The image build also hit an outage of the regional Ubuntu mirror (503 for
over 15 minutes); provision.sh now fails apt-get update on any missing
index and falls back to archive.ubuntu.com after three tries, restoring the
original sources before the image is sealed.

Result after the fixes (2026-11-19, ami-034d8e94160b0fecb): the setuptools
files have spaces in their names on the node ("script (dev).tmpl",
"launcher manifest.xml"), as expected. On redeploying the verifier, the
running workers showed the corrected-manifest path live: both files
"cleared ... matches the manifest now", the score went back to 100 at once
and the tier to healthy after 3 cycles; the earlier mount-bind finding
stayed, since critical is sticky. On fresh workers:

- check-probes.sh fails=0: canary found, sweep, 18-20 mount namespaces and
  an incremental log (1-43 new entries a challenge) on clean nodes, 60 s
  interval; an unknown binary seen 1.2 s after it ran (hint) and the node
  then at 15 s; A13 (runc changed, never run) critical at the next sweep;
  A15 (overlay over /usr/bin in a private namespace) critical as
  mount-overlay and mount-bind; a blocked canary critical as ima-canary
- check-scoring.sh fails=0 with the new scheduling and outage rule

Open point: the first full sweep of a boot does not finish in its 20 s
budget (4,000-6,700 of about 15,000 files); the rest are opened in later
full sweeps (every 10th challenge), so full coverage of a fresh boot takes
several of them.

## Step 4.6: join-time files (blueprint 10.4)

Files a worker gets when it joins are not in the AMI, so the signed
manifest cannot cover them. Until now the runtime policy allowed
/etc/kubernetes/, /var/lib/kubelet/, /etc/cni/net.d/ and /opt/cni/bin/
wholesale, so a changed kubelet config (A10) was not seen. These rules are
gone; what is left there is only what really changes on its own: kubelet
certificates and keys (checked by path), pod data and plugin sockets,
kubelet's empty temp files, and Calico's kubeconfig (its token rotates).
Everything else goes through pkg/joinref, in three layers:

1. Precomputed (join-reference.json, built by join-reference.sh):
   - from the launch template's user data, read from AWS: the discovery
     kubeconfig, the join configuration (a template filled per node with
     its zone and instance ID) and the cluster CA kubeadm writes from it
   - from two fresh workers, read over SSM right after the cluster is
     built: kubelet's config.yaml and instance-config.yaml, kubeadm's
     kubeadm-flags.env, kubelet.conf and Calico's CNI config. Node values
     (instance ID, zone, address, host name) are replaced by placeholders;
     the two workers must give the same templates, and every template,
     rendered for each worker, must equal that worker's file
   The verifier renders each template for the node it checks, from what
   EC2 says about the node (never what the node says)
2. Fleet consensus, for files that are the same on every node but cannot
   be read after the join (kubeadm deletes bootstrap-kubelet.conf) and for
   the binaries Calico installs (/opt/cni/bin, the FlexVolume driver): the
   hash reported by at least two nodes and by more than half of the nodes
   on the same AMI is accepted. A critical node does not vote, and a node
   that leaves takes its votes with it. Votes are saved in
   /var/lib/nodetrust-verifier/consensus.json
3. Trust on first use: with no such majority (one node, or a tie), the
   hash the fleet saw first is accepted

A join file that does not match counts against the score like any other
mismatch (Kubernetes config for /etc/kubernetes, the kubelet config and the
CNI config; system binaries for the CNI plugins).

Differences from the blueprint text:
- the blueprint renders kubeadm's files with kubeadm's own templates; here
  they are captured from two fresh workers and cross-checked instead (the
  same trust as the boot reference of step 4.1: a reviewed reference from
  known-clean nodes), because kubeadm's output format is not stable across
  versions
- the bootstrap token is one per cluster (in the launch template), not one
  per node issued by the verifier. The join reference holds it (in the join
  configuration template), so the file is root-only on the verifier host
  and reaches the service as a systemd credential

Also in this step: the first full sweep of a boot is repeated in the next
challenge until it finishes within its budget (step 4.5's open point).

Live check: check-join.sh (clean nodes with the narrowed policy; A10 gives
72.5, degraded, sudden; a changed kubeadm-flags.env; a changed CNI plugin
against the fleet).

First live run of 4.6: join-reference.sh passed (8 files, the same on both
workers after placeholders, every template rendering to each worker's
file), but the verifier then hung after its first challenge of each node.
Cause: the check that re-tests remembered files (Observation.Still) built
its join check inside Track.Observe, which runs under the daemon lock, and
the join check takes that lock: a deadlock as soon as a node had a sticky
file. Still is now prepared before the lock is taken, and a test runs
observe twice with a remembered file under a timeout (it fails on the old
code). The sticky file itself was a measurement violation on
/etc/cni/net.d/10-calico.conflist (read while Calico wrote it): the old
wholesale rule allowed such violations, so violations on join-reference and
consensus paths are allowed again (the content is measured when read).

Second run: the conflist file was a violation (stored hash empty), as
expected, and cleared on redeploy; clean workers healthy; A10 gave 72.5
(degraded, sudden); the changed CNI plugin was flagged by consensus. The
kubeadm-flags test showed what kubelet reads back when it restarts, which
the wholesale rule had hidden: allocated_pods_state, actuated_pods_state
and image_manager/ (records of pulled images). They are kubelet state, now
allowed as runtime. The test itself left a sed temp file in
/var/lib/kubelet (sed -i writes one), which was rightly reported; the test
now rewrites the file in place. Anything else under /var/lib/kubelet now
counts in the Kubernetes component instead of system binaries.

Third run: the kubelet state files cleared on redeploy; on fresh workers one
more path came up about 15 minutes in, /host/etc/cni/net.d/calico-kubeconfig:
calico-node rewrites its kubeconfig when the token is refreshed, through its
hostPath mount, so IMA logs the container-relative path. Allowed like the
host path.

Fourth run: check-join.sh fails=0 (clean workers healthy; A10 72.5
degraded sudden; kubeadm-flags.env 87.5; a changed CNI plugin 77.5).
check-scoring.sh failed once: after the reboot, worker 1 measured Calico's
/opt/cni/bin/loopback and portmap, and consensus flagged them. The AMI ships
those two plugins (kubernetes-cni) and Calico replaces them at join, so a
fresh node first measures the AMI's version and only later Calico's;
consensus had seen the AMI's first. Fix: the AMI's version stays a match
(it is in the manifest), and join-reference.sh now also records the hash of
every binary Calico installs (/opt/cni/bin, the FlexVolume driver), equal on
both reference workers, as accepted hashes. Consensus is left for files
that appear later and for bootstrap-kubelet.conf.

Fifth run (2026-11-19, ami-034d8e94160b0fecb): join-reference.sh recorded
24 installed binaries with the same hash on both workers (32 files in all);
check-join.sh fails=0 (A10 72.5 degraded sudden; kubeadm-flags.env 87.5;
a changed CNI plugin 77.5 against the join reference); check-scoring.sh
fails=0, including the reboot that failed before (the rebooted worker
measured Calico's plugins again and stayed at 90).

## Step 4.7: signed NodeTrust and the Phase 4 gate (blueprint 8.1, 11)

After every cycle the verifier publishes the node's state as a NodeTrust
object (trust.k8s-attest.io/v1alpha1, cluster-scoped, named by instance
ID). The state (tier, score, components, critical, findings, unattested
and why, files, drift, last attestation, reset and reboot counts, a
sequence number and the time) is serialised once and signed with ECDSA
P-256; the object's status holds the payload, the signature and the key ID,
plus readable copies of tier, score, critical, unattested and seq for
kubectl. Whoever acts on a NodeTrust (the Phase 5 controller) checks the
signature against the pinned public key, that the payload names the same
instance, that seq went up and that the update is recent, and then uses
only the payload. A copy edited in etcd or through the API is useless
without the key.

Writes go through server-side apply (field manager nodetrust-verifier) with
the stdlib HTTP client: the verifier logs in to the API server with a client
certificate (CN nodetrust-verifier) signed by the cluster CA in Terraform.
k8s/nodetrust.yaml holds the CRD, a ClusterRole that gives that user
NodeTrust and nothing else, and a ValidatingAdmissionPolicy that lets only
that user create, change or delete NodeTrust objects, so even the cluster
admin is refused. deploy-verifier.sh applies it on the control plane first.

nodetrust-check reads `kubectl get nodetrusts -o json` and checks every
item: `nodetrust-verifier nodetrust-check -pub pub.pem < list.json`.

Deviation: the signing key is generated in Terraform and given to the
verifier as a systemd credential. The blueprint wants it sealed in the
verifier's enclave; that is future work, the same as for the AK checks.

Drift window: the blueprint's 30 cycles assume 60-second cycles. With
adaptive intervals a changed node is challenged every 15 seconds, which
would shrink the window to 7.5 minutes exactly when drift is happening. The
window is kept as 30 minutes of time instead (TestTrackA11At15Seconds).

### Run

    cd infra/cluster && terraform apply && ./check-cluster.sh   # new: client cert and signing key
    cd ../phase3 && ./attest-cluster.sh
    cd ../phase4 && ./check-boot.sh && ./join-reference.sh
    ALLOWED_AMIS=ami-034d8e94160b0fecb ./deploy-verifier.sh
    ./check-nodetrust.sh                       # about 5 minutes
    ./replace-workers.sh && HOURS=4 ./phase4-gate.sh

check-nodetrust.sh: both workers have a NodeTrust that verifies with the
pinned key; seq goes up a minute later; a copy with the score edited to 100
fails; the cluster admin's status patch, delete and fake create are denied
by the admission policy; the verifier's user may write NodeTrust status but
not secrets or nodes; an unknown binary on worker 1 reaches the signed
state as warning 90.

phase4-gate.sh: every 5 minutes for HOURS hours, every worker must be
verified, healthy, 100, with nothing against it and a fresh signed
NodeTrust; then A11 (four small config edits five minutes apart: 95, 90,
85, 80, gradual drift, warning). Together with check-scoring.sh,
check-probes.sh and check-join.sh this covers the gate's exact scores.

### Result (2026-11-19, ami-034d8e94160b0fecb)

First run: everything held, but two checks of the script were wrong. The
"tampered" copy set a healthy node to healthy 100, which re-encoded to the
same bytes, so the signature was rightly valid; and kubectl auth can-i
exits 1 for "no", which mixed its warnings into the answer. Fixed: the
copy now changes the seq, the issue time and the tier, checks that the
bytes differ and is checked without the age limit; the RBAC check reads
only the yes/no lines.

Second run, fresh workers: check-nodetrust.sh fails=0. Both objects
verify with the pinned key; seq 4 -> 13 and 4 -> 12 over 75 s (a fresh
node is still on the 15 s interval); the edited copy fails with
"signature does not verify"; the admin's status patch, delete and fake
create are denied by the admission policy; the verifier's user may write
nodetrusts/status but not secrets or nodes; an unknown binary reached
worker 1's signed state as warning 90 within a minute.

### Phase 4 gate result (2026-11-19, ami-034d8e94160b0fecb)

Soak: 46 samples, every 5 minutes from 12:49 to 16:48 UTC (4 hours), on two
fresh workers: all 92 node samples verified, healthy, score 100, no file
against the node, no finding, no publish error, and every NodeTrust object
verified with the pinned key and was under 3 minutes old. (The script's own
soak line said FAIL because of a bug: the check printed an empty line for a
clean sample and the script counted any output as bad. Fixed;
gate-recount.sh recounts a run from its samples.jsonl.)

A11 (gradual drift) on worker 1, one config edit every 5 minutes:
sshd_config 95 isolated, sudoers 90 unclassified (tier warning), cron file
85 gradual, systemd unit 80 gradual; the node ended at warning 80, never
critical. With check-scoring.sh, check-probes.sh and check-join.sh (exact
scores for A1, A7-A10, A13, A15) this passes the Phase 4 gate. The soak
was 4 hours instead of the blueprint's 24.
