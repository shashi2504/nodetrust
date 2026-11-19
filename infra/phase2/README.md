# Phase 2: signed reference manifest

## Step 2.1: build the manifest

The manifest lists every file of the golden AMI's root filesystem, /boot and
the EFI system partition, with the SHA-256 of each regular file and the
mode, owner and file capabilities of everything (the ESP is FAT, so it has
no owners or modes). The verifier compares a node's IMA log against it.

It is built offline: a throwaway instance from stock Ubuntu (not the golden
AMI) mounts a volume made from the AMI's snapshot read-only and walks it.
The image being measured never measures itself, and no runtime files
(machine-id, ssh host keys, kubeadm output) get into the reference.

Checks the builder runs before it uploads:

- two builds give the same entries_sha256 (determinism)
- nothing on / is hidden under the /boot or /boot/efi mounts
- the files later phases rely on are present (kubelet, kubeadm, containerd,
  runc, kernel, initrd, grub.cfg, shim, IMA policy, build-info, module lock)
- dpkg cross-check: a second read of every packaged file must match the md5
  dpkg recorded at install time, and its SHA-256 must match the manifest.
  This is an independent check that the files were read correctly.

Then, locally: the downloaded .gz matches the builder's hash, entries_sha256
recomputes, and the manifest names the right AMI and snapshot.

Run (once per golden AMI):

```
cd infra/trust && terraform init && terraform apply && cd ../phase2
python3 -m unittest -v test_manifest
./build-manifest.sh ami-0ecbc5bf91f8cfc07
```

Output: manifest-<ami>.json.gz and manifest-<ami>-<time>.txt here, and the
same manifest in s3://<bucket>/manifests/<ami>/manifest.json.gz. The builder
and its volume are deleted at the end (KEEP=1 keeps them for debugging).

Manifest format (nodetrust.dev/manifest/v1): source (ami_id, snapshot_id,
region), build_info (from /etc/nodetrust/build-info), stats, entries sorted
by path, and entries_sha256 over the canonical JSON of the entries. Only
"created" differs between two builds of the same snapshot.

Result (2026-11-15, ami-0ecbc5bf91f8cfc07): 129,892 entries (108,078 files,
2.9 GB), entries_sha256 f9bb63de6c0592ea964bcad0b69752c34c20babd407219cb696c69adfa8041db,
same on both builds. dpkg cross-check: 97,628 packaged files read again, no
missing files and no md5 or SHA-256 mismatches. The first run failed on two
vim help files because the cross-check mishandled dpkg diversions (the
package that owns a diversion keeps its file at the original path); fixed
in manifest.py and covered by a test.

That image carried two kernels (1014, the one the builder booted, and 1017).
Fixed in provision.sh (phase1 step 1.5) and rebuilt as ami-0fa223dda38030b68:
90,990 entries, one kernel, dpkg cross-check clean on 64,493 files,
entries_sha256 a93a3c5dd243c5fa37ddbaa83b41dc5d264d8db6584dbcdfc4628bc5e237bf5d.
The old AMI and its snapshot are deregistered and deleted. Its signed
statement stays in the bucket history, so a valid signature alone must not
make an AMI trusted: the Phase 4 verifier also needs an allow-list of AMIs.

Not decided here: which paths the verifier ignores at runtime (for example
/var/lib/containerd, which collects a few hundred measured reads per image
pull). That is verifier policy (step 2.4 and Phase 4); the manifest records
the image as it is.

## Step 2.2: sign the manifest

The manifest is not signed directly. A short statement binds the AMI ID,
snapshot ID and region to the SHA-256 of the manifest (both the .gz bytes
and the uncompressed JSON) and to its entries_sha256. The statement's
SHA-256 is signed with the KMS key (ECC_NIST_P256, ECDSA_SHA_256). The
signature covers the exact statement bytes, so verifying needs no JSON
canonicalisation.

The verifier is given only the public key, pinned in
infra/trust/manifest-signing-key.pem. It checks, in order: the signature,
the statement's fields, that the statement is for the AMI the node runs,
then the manifest bytes against the signed hashes and that the manifest
names the same AMI and snapshot (pkg/manifest, used by the Phase 4
verifier).

```
cd infra/trust && terraform apply && cd ../phase2     # adds the KMS key
./sign-manifest.sh ami-0ecbc5bf91f8cfc07
```

The script downloads the manifest from the bucket, signs it, and verifies
the signature with KMS Verify, with openssl and the pinned key, and with the
Go verifier code. It also checks that a tampered statement and a wrong AMI
are rejected. Only then does it upload signed/<ami>/statement.json and
statement.sig. On the first run it writes the pinned key; commit that file.

Result (2026-11-15, ami-0fa223dda38030b68): KMS Verify, openssl and the Go
verifier all accept the signature; a tampered statement and a wrong AMI are
both rejected.

## Step 2.3: transparency log (Rekor)

The statement's SHA-256, the signature and the public signing key are
recorded in the public Rekor v1 log (rekor.sigstore.dev) as a hashedrekord
entry. The statement and manifest themselves stay private. This makes every
signature with our key publicly visible with a time: a manifest signed with
a stolen key but never logged, or logged after the fact, can be told apart.

The saved entry (signed/<ami>/rekor-entry.json) is checked offline by
pkg/manifest with the pinned Rekor key (infra/trust/rekor-public-key.pem):

- the entry is for this statement's hash, this signature and the pinned
  signing key, and comes from the pinned log
- Rekor's signed entry timestamp over the entry is valid
- the RFC 6962 inclusion proof leads from the entry to the tree root
- Rekor's signed checkpoint commits to that root and tree size

```
./log-rekor.sh ami-0fa223dda38030b68
```

Running it again is safe: Rekor answers 409 for an entry it already has and
the script fetches and checks the existing one.

Result (2026-11-15, ami-0fa223dda38030b68): logged as entry 3904487387
(https://search.sigstore.dev/?logIndex=3904487387); the offline check passed
(signed entry timestamp, inclusion proof to tree size 3,782,583,180, signed
checkpoint), and edited copies were rejected. The pinned log ID c0d23d6a...
is the published ID of rekor.sigstore.dev.

Why v1 and not Rekor v2: Sigstore keeps v1 as the public default for now,
while v2 log URLs rotate every few months and are meant to be found through
Sigstore's TUF signing config. Moving to v2 means verifying a tile-based
proof and an RFC 3161 timestamp instead of integratedTime; noted as later
work. The Rekor key is pinned on first use; a stronger source is the key
published in Sigstore's TUF trusted root.

## Step 2.4: check a live node against the manifest

check-node.sh takes a worker's attested IMA measurements and checks every
one against the signed manifest of the AMI the worker runs:

- on the node: read SHA-256 PCR 10, then the IMA log, keep the shortest log
  prefix that replays to the PCR (only that part is attested), and write each
  distinct (path, SHA-256) pair to a snapshot (node/ima_snapshot.py)
- then tamper on purpose: add /usr/local/bin/nt-evil and run it, append
  bytes to /usr/bin/whoami and run it; take a second snapshot
- on the laptop: verify the manifest chain (signature, AMI, hashes, Rekor)
  and classify both snapshots with the Go verifier (pkg/imapolicy)

Classes: match (in the manifest, same hash), mismatch (in the manifest,
different hash, no rule allows it), changed (differs, but a mutable rule
allows it), runtime (not in the manifest, a runtime rule expects it),
unknown (not in the manifest, no rule), violation, aggregate
(boot_aggregate). A node passes when it has no mismatch and no unknown.

runtime-policy.json is the first version of the verifier's file policy.
Every rule names a path (exact, directory prefix, or glob) and a reason.
Files inside containers are not measured at all (the IMA policy skips
overlayfs), so container images need their own control.

The step passes when the second snapshot reports nt-evil as unknown and
whoami as mismatch. The baseline result is listed separately: on the first
run it shows which runtime paths the policy does not cover yet.

```
cd infra/cluster && terraform apply && ./check-cluster.sh
W=$(aws autoscaling describe-auto-scaling-groups --auto-scaling-group-names nodetrust-workers \
    --query 'AutoScalingGroups[0].Instances[0].InstanceId' --output text)
cd ../phase2 && ./check-node.sh "$W"
```

Rerun the classification offline after editing the policy or re-signing
the manifest (no cluster needed): `./recheck.sh node-<instance>-<time>`.

First run (2026-11-16, worker of ami-0fa223dda38030b68, 2,644 attested
measurements): tamper detection passed (nt-evil unknown, whoami mismatch,
neither in the baseline). The baseline had 2,220 matches and 371 runtime
hits, plus 4 mismatches, 34 unknowns and 4 violations that led to these
changes:

- the manifest did not cover snaps: /snap/<name>/<rev> is a mounted
  squashfs image, and the SSM agent runs from it. remote-build.sh now mounts
  every snap in the image and adds its files (manifest rebuilt and re-signed)
- mutable: /etc/resolv.conf (DHCP DNS), /boot/grub/grubenv (GRUB boot state;
  what GRUB loads is in PCRs 8-9)
- runtime: DHCP lease, cloud-init's working directory and temp files,
  snapd state, kube-proxy's ConfigMap and the Calico CNI and FlexVolume
  binaries
- rules can now also pin content: temp files are only allowed if empty
- a violation counts only when a rule covers its path (journal, fresh
  kubelet certificate, SSM output); a violation anywhere else is unknown

Two findings for the thesis. IMA records paths relative to the reading
process's mount namespace, so a pod volume read inside a container shows up
under the container's path (/var/lib/kube-proxy/..., /host/opt/cni/bin/...),
and a path rule cannot tell that from the same path on the host. And
Calico installs root executables on the host at runtime (CNI plugins, the
FlexVolume driver); they come from the Calico image, so the AMI manifest
cannot vouch for them. Pinning their hashes per Calico version is the
obvious next step.
