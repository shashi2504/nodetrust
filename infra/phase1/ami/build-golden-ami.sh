#!/usr/bin/env bash
# Step 1.2: build the golden worker AMI.
#
#   1. launch a builder instance from the base AMI (Secure Boot + NitroTPM)
#   2. user data runs provision.sh, which configures the node and powers off
#   3. snapshot the root volume and register it with UEFI boot, NitroTPM v2.0,
#      IMDSv2 only and the builder's Secure Boot variable store (the pinned
#      store plus Ubuntu's dbx update, applied while the builder booted)
#   4. terminate the builder
#
# Usage: ./build-golden-ami.sh <base-ami-id>
# Env:   K8S_MINOR (default v1.35), INSTANCE_TYPE (default m6i.large),
#        ROOT_GB (default 30), BUILD_TIMEOUT_MIN (default 40)
# Prints the golden AMI ID on stdout. On a failed build the builder is left
# running so you can inspect it through SSM; its console output is printed.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../lib.sh
. ../lib.sh
need aws curl sha256sum gzip base64 awk terraform go python3

BASE_AMI="${1:-}"
[ -n "$BASE_AMI" ] || die "usage: $0 <base-ami-id>"
REGION="$(region)"
aws_ready
K8S_MINOR="${K8S_MINOR:-v1.35}"
INSTANCE_TYPE="${INSTANCE_TYPE:-m6i.large}"
ROOT_GB="${ROOT_GB:-30}"
BUILD_TIMEOUT_MIN="${BUILD_TIMEOUT_MIN:-40}"
[[ "$K8S_MINOR" =~ ^v1\.[0-9]+$ ]] || die "K8S_MINOR must look like v1.35"

tpm="$(aws ec2 describe-images --region "$REGION" --image-ids "$BASE_AMI" --query 'Images[0].TpmSupport' --output text)"
[ "$tpm" = "v2.0" ] || die "$BASE_AMI has TpmSupport=$tpm; use the base AMI from 01-register-base-ami.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log "fetching the pinned Secure Boot variable store"
fetch_sb_blob "$WORK/blob.bin"

# The nodetrust agent (Phase 3): built here, shipped to the builder through a
# presigned URL on the trust bucket, checked by SHA-256 on the builder.
REPO="$(cd ../../.. && pwd)"
BUCKET="$(terraform -chdir="$REPO/infra/trust" output -raw manifest_bucket 2>/dev/null)" ||
	die "no trust stack outputs; run 'terraform apply' in infra/trust first"
CA_B64="$(terraform -chdir="$REPO/infra/trust" output -raw verifier_ca_pem 2>/dev/null | base64 -w0)"
[ -n "$CA_B64" ] || die "no verifier CA in the trust stack; run 'terraform init -upgrade && terraform apply' in infra/trust"
log "building the nodetrust agent"
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$WORK/nodetrust-agent" ./cmd/agent)
AGENT_SHA="$(sha256sum "$WORK/nodetrust-agent" | cut -d' ' -f1)"
AGENT_KEY="tools/agent-$AGENT_SHA"
aws s3 cp --region "$REGION" --only-show-errors "$WORK/nodetrust-agent" "s3://$BUCKET/$AGENT_KEY"
AGENT_URL="$(aws s3 presign --region "$REGION" --expires-in 3600 "s3://$BUCKET/$AGENT_KEY")"
trap 'rm -rf "$WORK"; aws s3 rm --region "$REGION" --only-show-errors "s3://$BUCKET/$AGENT_KEY" || true' EXIT

# User data: a small wrapper that unpacks provision.sh and runs it.
python3 -c '
import sys
k8s, url, sha, ca = sys.argv[1:5]
s = sys.stdin.read()
for k, v in (("@@K8S_MINOR@@", k8s), ("@@AGENT_URL@@", url), ("@@AGENT_SHA256@@", sha), ("@@VERIFIER_CA_B64@@", ca)):
    s = s.replace(k, v)
sys.stdout.write(s)' "$K8S_MINOR" "$AGENT_URL" "$AGENT_SHA" "$CA_B64" <provision.sh >"$WORK/provision.sh"
if grep -q '@@' "$WORK/provision.sh"; then
	die "provision.sh still has unfilled placeholders"
fi
cat >"$WORK/userdata.tmpl" <<'EOF'
#!/bin/bash
set -euo pipefail
base64 -d <<'NT_PROVISION_EOF' | gunzip >/root/nodetrust-provision.sh
@@PROVISION_B64@@
NT_PROVISION_EOF
exec bash /root/nodetrust-provision.sh
EOF
embed_files "$WORK/userdata.tmpl" "$WORK/userdata" "@@PROVISION_B64@@=$WORK/provision.sh"

ensure_ssm_role
SG="$(ensure_no_inbound_sg "$REGION" nodetrust-probe)"

log "launching the builder ($INSTANCE_TYPE, ${ROOT_GB} GB root, Kubernetes $K8S_MINOR)"
ID="$(aws ec2 run-instances --region "$REGION" \
	--image-id "$BASE_AMI" \
	--instance-type "$INSTANCE_TYPE" \
	--iam-instance-profile "Name=$SSM_ROLE" \
	--security-group-ids "$SG" \
	--block-device-mappings "DeviceName=/dev/sda1,Ebs={VolumeSize=$ROOT_GB,VolumeType=gp3,DeleteOnTermination=true}" \
	--metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled" \
	--user-data "file://$WORK/userdata" \
	--tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=nodetrust-ami-builder},{$PROJECT_TAG}]" \
	--query 'Instances[0].InstanceId' --output text)"
log "builder $ID running; provisioning takes about 10-15 minutes"

console() {
	aws ec2 get-console-output --region "$REGION" --instance-id "$ID" --latest \
		--query Output --output text 2>/dev/null || true
}

result=""
deadline=$((SECONDS + BUILD_TIMEOUT_MIN * 60))
while [ "$SECONDS" -lt "$deadline" ]; do
	# Only lines that start with the marker count: provision.sh runs with
	# set -x, so its trap definition echoes "+ trap ... NODETRUST_BUILD_RESULT=failed"
	# long before any result exists.
	result="$(console | tr -d '\r' | grep -E '^[[:space:]]*NODETRUST_BUILD_RESULT=(ok$|failed)' |
		tail -1 | sed 's/^[[:space:]]*//' || true)"
	[ -n "$result" ] && break
	sleep 30
done

if [ "$result" != "NODETRUST_BUILD_RESULT=ok" ]; then
	echo "----- last 60 lines of the builder console -----" >&2
	console | tail -60 >&2
	die "build did not finish cleanly (${result:-timed out after $BUILD_TIMEOUT_MIN min}). Builder $ID is left running; inspect it with: aws ssm start-session --target $ID"
fi

log "provisioning finished; waiting for the builder to stop"
aws ec2 wait instance-stopped --region "$REGION" --instance-ids "$ID"

VOL="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" \
	--query "Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName=='/dev/sda1'].Ebs.VolumeId | [0]" \
	--output text)"
[ -n "$VOL" ] && [ "$VOL" != None ] || die "could not find the builder's root volume"

# The AMI takes the builder's UEFI variable store, not the pinned one it
# started from. The builder booted with Secure Boot on Canonical's store, and
# at boot secureboot-db (sbkeysync) inserted Ubuntu's dbx update
# (/usr/share/secureboot/updates/dbx) into dbx. Registering the pinned store
# again would make every worker apply that update on its first boot, so dbx,
# and PCR 7, would differ between a worker's first and second boot (seen in
# step 4.3, 2026-11-18). With the builder's store, workers start with the
# revocations in place and secureboot-db finds nothing to do.
log "reading the builder's UEFI variable store"
aws ec2 get-instance-uefi-data --region "$REGION" --instance-id "$ID" \
	--query UefiData --output text | tr -d '[:space:]' >"$WORK/builder-uefi.b64"
[ -s "$WORK/builder-uefi.b64" ] || die "could not read the UEFI variable store of $ID"
log "builder variable store: $(base64 -d "$WORK/builder-uefi.b64" | wc -c) bytes (pinned store: $(base64 -d "$WORK/blob.bin" 2>/dev/null | wc -c) bytes)"

STAMP="$(date -u +%Y%m%d%H%M)"
log "snapshotting $VOL"
SNAP="$(aws ec2 create-snapshot --region "$REGION" --volume-id "$VOL" \
	--description "nodetrust golden worker $STAMP" \
	--tag-specifications "ResourceType=snapshot,Tags=[{$PROJECT_TAG},{Key=base-ami,Value=$BASE_AMI}]" \
	--query SnapshotId --output text)"
aws ec2 wait snapshot-completed --region "$REGION" --snapshot-ids "$SNAP"

NAME="nodetrust-worker-k8s-${K8S_MINOR}-$STAMP"
log "registering $NAME"
AMI="$(aws ec2 register-image --region "$REGION" \
	--name "$NAME" \
	--description "nodetrust golden worker: Kubernetes $K8S_MINOR, IMA policy, hardening; from $BASE_AMI" \
	--uefi-data "$(cat "$WORK/builder-uefi.b64")" \
	--block-device-mappings "DeviceName=/dev/sda1,Ebs={SnapshotId=$SNAP,DeleteOnTermination=true,VolumeType=gp3}" \
	--architecture x86_64 \
	--root-device-name /dev/sda1 \
	--virtualization-type hvm \
	--ena-support \
	--boot-mode uefi \
	--tpm-support v2.0 \
	--imds-support v2.0 \
	--tag-specifications "ResourceType=image,Tags=[{$PROJECT_TAG},{Key=base-ami,Value=$BASE_AMI},{Key=k8s-minor,Value=$K8S_MINOR},{Key=role,Value=worker}]" \
	--query ImageId --output text)"
aws ec2 wait image-available --region "$REGION" --image-ids "$AMI"

log "terminating the builder"
aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null

aws ec2 describe-images --region "$REGION" --image-ids "$AMI" \
	--query 'Images[0].{BootMode:BootMode,TpmSupport:TpmSupport,ImdsSupport:ImdsSupport,Name:Name}' --output table >&2
echo "$AMI"
