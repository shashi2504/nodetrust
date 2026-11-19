# Phase 3: node agent

## Step 3.1: TPM layer

See the top-level README: pkg/attest (verifier side, standard library only)
and pkg/agent (TPM side, go-tpm), checked against go-tpm, the TPM reference
simulator (make test-sim) and swtpm.

## Step 3.2: enrollment and a quote on NitroTPM

enroll-node.sh runs the real agent binary on a golden-AMI instance through
SSM and the verifier code on the laptop:

1. the agent is built here (static linux/amd64) and fetched by the node from
   a presigned S3 URL that expires in 15 minutes; its SHA-256 is checked on
   the node before it is installed
2. agent enroll-request: the EK and AK public areas
3. verifier enroll-challenge: the EK must be the TCG RSA-2048 EK (template
   attributes, PolicySecret(endorsement), AES-128-CFB) and equal to
   ec2:GetInstanceTpmEkPub for the instance; the AK must be a restricted,
   fixedTPM signing key. A 32-byte secret is protected for that EK and the
   AK's name (software MakeCredential)
4. agent activate: the TPM releases the secret only if the AK named in the
   credential is loaded in the TPM that holds that EK; verifier enroll-finish
   compares it and writes enrolled.json
5. agent quote with a fresh 32-byte nonce: SHA-256 PCRs 0-10 and the IMA log
   read after the quote; verifier check-quote checks the AK signature, the
   nonce, the PCR digest, and that a prefix of the log replays to PCR 10

Negative checks: a secret from a second challenge does not complete the
first, and the same quote with another nonce is rejected. A second
enroll-request must show the same AK, because both keys are derived from
the TPM's seeds and nothing is stored on the node.

The AK is a primary key in the endorsement hierarchy, not the owner
hierarchy. For a signing key outside the endorsement and platform
hierarchies the TPM obfuscates resetCount, restartCount and the firmware
version in quotes (swtpm showed resetCount 3089743877 with an owner-hierarchy
AK), and the verifier needs the real resetCount to notice reboots.

The instance ID used is always the one the verifier asked the cloud about,
never the one the agent reports (a mismatch is printed as WARN).

```
cd infra/phase1
ID=$(PROBE_MODE=golden ./02-launch-probe.sh ami-0fa223dda38030b68) && echo "ID=$ID"
cd ../phase3 && ./enroll-node.sh "$ID"
cd ../phase1 && ./99-cleanup-probe.sh "$ID"
```

Result (2026-11-16, i-0f443f46ed3c29e4c on ami-0fa223dda38030b68): all 11
checks passed. The quote covered PCRs 0-10, and 2,423 IMA entries replayed to
PCR 10. resetCount=3 (real, not obfuscated). PCRs 2, 3 and 6 are 3d458cfe...,
the value of a PCR that saw only the separator event. These are provisional
boot references until step 3.3 shows them on more than one instance.

Development: the agent accepts NODETRUST_TPM_DEVICE=tcp:HOST:PORT (swtpm) and NODETRUST_EVENTLOG=none (no firmware log)
and NODETRUST_IMA_LOG=FILE. The whole script was run this way against swtpm
with stand-ins for the AWS CLI before the first NitroTPM run.

## Step 3.3: the agent as a service

The golden AMI now runs `nodetrust-agent serve` at boot (systemd, before
kubelet): HTTPS on 9443, TLS 1.3 only, three POST endpoints carrying the
same messages as step 3.2 (/v1/enroll, /v1/activate, /v1/quote).

Who may call it: only a client certificate issued by the verifier CA (trust
stack, infra/trust/verifier-ca.tf) with the common name nodetrust-verifier.
Pods can reach their node's address, so the security group alone is not
enough. The CA certificate is baked into the AMI, so the signed manifest
covers it.

Which agent the verifier talks to: the agent's TLS key is new at every
start and never stored, and the verifier does not check it against any CA.
Instead every quote signs SHA-256("nodetrust-quote-binding/v1" || nonce ||
SHA-256(agent TLS key)) as qualifying data (protocol.BindNonce). A relay
that terminates TLS with its own key, even with a valid client certificate,
makes the verifier compute a different value, and the quote fails (tested
in pkg/verifier with a TLS-terminating reverse proxy). Enrollment needs no
channel trust: only the TPM can release the secret.

The unit runs as root (the IMA log is mode 0440 root:root) with an empty
capability bounding set, the tss group for /dev/tpmrm0, a read-only file
system and a closed device policy. The probe checks the binary hash against
build-info, the service, the listener, the empty capability set, that an
anonymous request is refused, and that the binary is in the IMA log.

Local test before the cluster run: two agents with two swtpm TPMs on
127.0.0.2 and 127.0.0.3:9443, the real attest-cluster.sh, and stand-ins for
the AWS CLI: every check passed, and swapping the cloud EKs of the two
"workers" made enrollment fail.

Run (the trust stack gets the CA, then a new AMI, its manifest, a cluster):

```
cd infra/trust && terraform init -upgrade && terraform apply          # +5: CA and client cert
cd ../phase1
GOLDEN=$(./ami/build-golden-ami.sh ami-0d9cf6e2a0d483386) && echo "GOLDEN=$GOLDEN"
ID=$(PROBE_MODE=golden ./02-launch-probe.sh "$GOLDEN") && echo "ID=$ID"
PROBE_MODE=golden ./03-run-probe.sh "$ID"                              # 57 checks
./99-cleanup-probe.sh "$ID"
cd ../phase2
./build-manifest.sh "$GOLDEN" && ./sign-manifest.sh "$GOLDEN" && ./log-rekor.sh "$GOLDEN"
cd ../cluster
echo "worker_ami = \"$GOLDEN\"" > terraform.tfvars
terraform apply && ./check-cluster.sh
cd ../phase3 && ./attest-cluster.sh
cd ../phase2 && ./check-node.sh "$(aws autoscaling describe-auto-scaling-groups \
  --auto-scaling-group-names nodetrust-workers \
  --query 'AutoScalingGroups[0].Instances[0].InstanceId' --output text)"
cd ../cluster && terraform destroy
```

Result (2026-11-16, ami-07deef95f949d1d5d, two workers):

- probe 57/57 including the six agent checks; the manifest holds the agent
  binary at the hash the probe measured; signed and logged (Rekor 3911877814)
- attest-cluster.sh from the verifier host: both workers enrolled over mTLS
  (EK equals EC2's), two TLS-bound quotes each (IMA logs of 2,659 and 2,708
  entries replay), and both refused a request with no client certificate
  and one with a self-signed nodetrust-verifier certificate
- PCR 0 and PCRs 2-9 identical on both workers and identical to the step 3.2
  probe on the previous AMI. PCR 1 (platform configuration: SMBIOS, ACPI,
  boot variables) differs per instance, so it needs event-log checks rather
  than a fixed value (Phase 4)
- PCR 9 did not change between the two AMIs although the initrd did, so on
  this boot path the initrd contents are not measured into PCRs 0-9. Partly
  covered: IMA's boot (tcb) policy measures what the initramfs executes.
  Phase 4 reads the boot event log to pin down what PCR 9 holds
- check-node.sh: tamper detection passed (nt-evil unknown, whoami mismatch);
  the agent binary is a match. The baseline had three empty snapd cache temp
  files; runtime-policy.json now allows /var/cache/snapd/ for empty files only
