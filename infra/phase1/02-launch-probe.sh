#!/usr/bin/env bash
# Launch one probe instance.
#
# Step 1.1: from the base AMI. User data installs tpm2-tools, turns IMA on with
#           the built-in tcb policy and reboots once.
# Step 1.2: from the golden AMI, with PROBE_MODE=golden. User data only drops
#           the probe files; IMA, the policy and tpm2-tools are already in the AMI.
#
# The instance gets no SSH key and a security group with no inbound rules.
# Access is through SSM only. It runs in the default VPC with a public IP so it
# can reach SSM (and apt in step 1.1); the cluster (step 1.3) uses private subnets.
#
# Usage: [PROBE_MODE=golden] ./02-launch-probe.sh <ami-id>
# Env:   INSTANCE_TYPE (default m6i.large)
# Prints the instance ID on stdout.
set -euo pipefail
cd "$(dirname "$0")"
. ./lib.sh
need aws gzip base64 awk

AMI_ID="${1:-}"
[ -n "$AMI_ID" ] || die "usage: [PROBE_MODE=golden] $0 <ami-id>"
REGION="$(region)"
aws_ready
INSTANCE_TYPE="${INSTANCE_TYPE:-m6i.large}"
case "${PROBE_MODE:-base}" in
base) TMPL=probe-userdata.sh.tmpl ;;
golden) TMPL=golden-userdata.sh.tmpl ;;
*) die "PROBE_MODE must be base or golden" ;;
esac
[ -f "$TMPL" ] || die "$TMPL is missing; extract the complete infra/phase1 folder"

tpm="$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI_ID" --query 'Images[0].TpmSupport' --output text)"
[ "$tpm" = "v2.0" ] || die "$AMI_ID has TpmSupport=$tpm; it must be registered with NitroTPM"

ensure_ssm_role
SG="$(ensure_no_inbound_sg "$REGION" nodetrust-probe)"

USERDATA="$(mktemp)"
trap 'rm -f "$USERDATA" "$USERDATA.tmp"' EXIT
embed_files "$TMPL" "$USERDATA" "@@PROBE_SH_B64@@=probe.sh" "@@IMA_REPLAY_B64@@=ima_replay.py"

log "launching $INSTANCE_TYPE from $AMI_ID (${PROBE_MODE:-base} mode, user data $(wc -c <"$USERDATA") bytes)"
ID="$(aws ec2 run-instances --region "$REGION" \
	--image-id "$AMI_ID" \
	--instance-type "$INSTANCE_TYPE" \
	--iam-instance-profile "Name=$SSM_ROLE" \
	--security-group-ids "$SG" \
	--metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled" \
	--user-data "file://$USERDATA" \
	--tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=nodetrust-probe},{$PROJECT_TAG}]" \
	--query 'Instances[0].InstanceId' --output text)"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
log "running; probe files land within a few minutes (step 1.1 also reboots once)"
echo "$ID"
