#!/usr/bin/env bash
# Step 1.1a: register a Secure Boot + NitroTPM base AMI from stock Ubuntu 24.04.
#
# Ubuntu's EC2 AMIs boot UEFI-capable but ship without Secure Boot keys and
# without the NitroTPM flag, and NitroTPM can only be set when an AMI is
# registered. So we copy the root snapshot of the current Ubuntu 24.04 AMI and
# register it again with:
#   --boot-mode uefi, --tpm-support v2.0, --imds-support v2.0, and
#   --uefi-data = Canonical's prebuilt Secure Boot variable store.
# Recipe: https://documentation.ubuntu.com/aws/aws-how-to/security/use-secureboot-and-vtpm
#
# Usage: ./01-register-base-ami.sh
# Prints the new AMI ID on the last line.
set -euo pipefail
cd "$(dirname "$0")"
. ./lib.sh
need aws curl sha256sum

REGION="$(region)"
aws_ready
BLOB_URL="https://github.com/canonical/aws-secureboot-blob/releases/latest/download/blob.bin"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log "downloading Canonical's Secure Boot variable store"
curl -fsSL -o "$WORK/blob.bin" "$BLOB_URL"
log "blob.bin sha256: $(sha256sum "$WORK/blob.bin" | cut -d' ' -f1)  (record this in the README)"

log "looking up the current Ubuntu 24.04 AMI in $REGION"
SRC_AMI=""
ssm_err=""
for vol in ebs-gp3 ebs-gp2; do
	param="/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/$vol/ami-id"
	if SRC_AMI="$(aws ssm get-parameter --region "$REGION" --name "$param" \
		--query Parameter.Value --output text 2>"$WORK/ssm.err")"; then
		[ -n "$SRC_AMI" ] && [ "$SRC_AMI" != None ] && break
	fi
	ssm_err="$param: $(tr '\n' ' ' <"$WORK/ssm.err")"
	SRC_AMI=""
done
[ -n "$SRC_AMI" ] || die "could not find the Ubuntu 24.04 AMI through SSM. Last error: ${ssm_err:-none}"

SRC_NAME="$(aws ec2 describe-images --region "$REGION" --image-ids "$SRC_AMI" --query 'Images[0].Name' --output text)"
SRC_SNAP="$(aws ec2 describe-images --region "$REGION" --image-ids "$SRC_AMI" \
	--query 'Images[0].BlockDeviceMappings[0].Ebs.SnapshotId' --output text)"
log "source: $SRC_AMI ($SRC_NAME), root snapshot $SRC_SNAP"

log "copying the root snapshot"
NEW_SNAP="$(aws ec2 copy-snapshot --region "$REGION" --source-region "$REGION" \
	--source-snapshot-id "$SRC_SNAP" \
	--description "nodetrust base from $SRC_AMI" \
	--tag-specifications "ResourceType=snapshot,Tags=[{$PROJECT_TAG},{Key=source-ami,Value=$SRC_AMI}]" \
	--query SnapshotId --output text)"
aws ec2 wait snapshot-completed --region "$REGION" --snapshot-ids "$NEW_SNAP"

NAME="nodetrust-base-${SRC_NAME##*/}-$(date -u +%Y%m%d%H%M)"
log "registering $NAME"
NEW_AMI="$(aws ec2 register-image --region "$REGION" \
	--name "$NAME" \
	--description "Ubuntu 24.04 + Secure Boot (Canonical blob) + NitroTPM, from $SRC_AMI" \
	--uefi-data "$(cat "$WORK/blob.bin")" \
	--block-device-mappings "DeviceName=/dev/sda1,Ebs={SnapshotId=$NEW_SNAP,DeleteOnTermination=true,VolumeType=gp3}" \
	--architecture x86_64 \
	--root-device-name /dev/sda1 \
	--virtualization-type hvm \
	--ena-support \
	--boot-mode uefi \
	--tpm-support v2.0 \
	--imds-support v2.0 \
	--tag-specifications "ResourceType=image,Tags=[{$PROJECT_TAG},{Key=source-ami,Value=$SRC_AMI}]" \
	--query ImageId --output text)"
aws ec2 wait image-available --region "$REGION" --image-ids "$NEW_AMI"

log "registered image attributes:"
aws ec2 describe-images --region "$REGION" --image-ids "$NEW_AMI" \
	--query 'Images[0].{BootMode:BootMode,TpmSupport:TpmSupport,ImdsSupport:ImdsSupport,Name:Name}' --output table >&2

echo "$NEW_AMI"
