#!/usr/bin/env bash
# Step 2.1: build the reference manifest for a golden AMI.
#
#   1. launch a throwaway builder from stock Ubuntu 24.04 (not the golden AMI:
#      the image being measured never measures itself)
#   2. make a volume from the golden AMI's snapshot and attach it to the
#      builder after boot (attaching before boot could let the builder boot
#      from the copy, since both have the same filesystem labels)
#   3. remote-build.sh mounts it read-only, builds the manifest twice,
#      cross-checks it against dpkg and uploads it to the trust bucket
#   4. download it here and recheck its digest
#   5. terminate the builder and delete the volume
#
# Usage: ./build-manifest.sh <golden-ami-id>
# Needs: infra/trust applied (bucket and builder role).
# Env:   INSTANCE_TYPE (default m6i.large), KEEP=1 keeps the builder and
#        volume for debugging (delete them yourself afterwards).
# Writes manifest-<ami>.json.gz and manifest-<ami>-<time>.txt here.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3 sha256sum tar gzip base64

AMI="${1:-}"
[ -n "$AMI" ] || die "usage: $0 <golden-ami-id>"
REGION="$(region)"
aws_ready
INSTANCE_TYPE="${INSTANCE_TYPE:-m6i.large}"

BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket 2>/dev/null)" ||
	die "no trust stack outputs; run 'terraform init && terraform apply' in infra/trust first"
PROFILE="$(terraform -chdir=../trust output -raw builder_instance_profile)"

role="$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI" \
	--query "Images[0].Tags[?Key=='role'].Value | [0]" --output text)"
[ "$role" = worker ] || die "$AMI is not tagged role=worker; pass the golden AMI, not the base AMI"
SNAP="$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI" \
	--query "Images[0].BlockDeviceMappings[?DeviceName=='/dev/sda1'].Ebs.SnapshotId | [0]" --output text)"
[[ "$SNAP" == snap-* ]] || die "could not find the root snapshot of $AMI (got '$SNAP')"
nmap="$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI" \
	--query "length(Images[0].BlockDeviceMappings[?Ebs])" --output text)"
[ "$nmap" = 1 ] || die "$AMI has $nmap EBS volumes; the manifest builder expects one"

BUILDER_AMI="$(aws ssm get-parameter --region "$REGION" \
	--name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id \
	--query Parameter.Value --output text)"
SG="$(ensure_no_inbound_sg "$REGION" nodetrust-probe)"

ID="" VOL=""
cleanup() {
	local rc=$?
	if [ "${KEEP:-0}" = 1 ]; then
		log "KEEP=1: leaving builder ${ID:-none} and volume ${VOL:-none}"
		exit "$rc"
	fi
	if [ -n "$ID" ]; then
		log "terminating builder $ID"
		aws ec2 terminate-instances --region "$REGION" --instance-ids "$ID" >/dev/null || true
		aws ec2 wait instance-terminated --region "$REGION" --instance-ids "$ID" || true
	fi
	if [ -n "$VOL" ]; then
		log "deleting volume $VOL"
		aws ec2 wait volume-available --region "$REGION" --volume-ids "$VOL" || true
		aws ec2 delete-volume --region "$REGION" --volume-id "$VOL" || true
	fi
	exit "$rc"
}
trap cleanup EXIT

log "launching manifest builder ($INSTANCE_TYPE, stock Ubuntu $BUILDER_AMI)"
ID="$(aws ec2 run-instances --region "$REGION" \
	--image-id "$BUILDER_AMI" \
	--instance-type "$INSTANCE_TYPE" \
	--iam-instance-profile "Name=$PROFILE" \
	--security-group-ids "$SG" \
	--metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled" \
	--tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=nodetrust-manifest-builder},{$PROJECT_TAG}]" \
	--query 'Instances[0].InstanceId' --output text)"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$ID"
AZ="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$ID" \
	--query 'Reservations[0].Instances[0].Placement.AvailabilityZone' --output text)"

log "creating a volume from $SNAP in $AZ"
VOL="$(aws ec2 create-volume --region "$REGION" --snapshot-id "$SNAP" \
	--availability-zone "$AZ" --volume-type gp3 \
	--tag-specifications "ResourceType=volume,Tags=[{Key=Name,Value=nodetrust-manifest-source},{$PROJECT_TAG}]" \
	--query VolumeId --output text)"
aws ec2 wait volume-available --region "$REGION" --volume-ids "$VOL"

log "waiting for SSM on $ID"
wait_ssm_online "$REGION" "$ID" 10 || die "builder $ID did not come online in SSM within 10 minutes"

log "attaching $VOL"
aws ec2 attach-volume --region "$REGION" --volume-id "$VOL" --instance-id "$ID" --device /dev/sdf >/dev/null
for _ in $(seq 1 60); do
	st="$(aws ec2 describe-volumes --region "$REGION" --volume-ids "$VOL" \
		--query 'Volumes[0].Attachments[0].State' --output text)"
	[ "$st" = attached ] && break
	sleep 5
done
[ "$st" = attached ] || die "$VOL did not attach (state $st)"

payload="$(tar -C "$HERE" -czf - manifest.py remote-build.sh | base64 -w0)"
REPORT="manifest-$AMI-$(date +%Y%m%d%H%M).txt"
log "building the manifest on the builder (usually 5-15 minutes: the volume loads from the snapshot on first read)"
rc=0
run_ssm "$REGION" "$ID" "rm -rf /root/nt && mkdir -p /root/nt && cd /root/nt && echo $payload | base64 -d | tar xz && bash remote-build.sh $VOL $AMI $SNAP $BUCKET $REGION" >"$REPORT" || rc=$?
cat "$REPORT"
[ "$rc" -eq 0 ] || die "remote build failed; see $REPORT (rerun with KEEP=1 to inspect the builder)"

# --- local checks ----------------------------------------------------------------------
LOCAL_FAILS=0
lpass() { printf 'PASS %-26s %s\n' "$1" "$2" | tee -a "$REPORT"; }
lfail() {
	printf 'FAIL %-26s %s\n' "$1" "$2" | tee -a "$REPORT"
	LOCAL_FAILS=$((LOCAL_FAILS + 1))
}

OUT="manifest-$AMI.json.gz"
aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/manifests/$AMI/manifest.json.gz" "$OUT"
want_sha="$(awk '$1 == "INFO" && $2 == "manifest-gz-sha256" { print $3 }' "$REPORT")"
got_sha="$(sha256sum "$OUT" | cut -d' ' -f1)"
if [ -n "$want_sha" ] && [ "$got_sha" = "$want_sha" ]; then
	lpass download "$OUT sha256 $got_sha matches the builder"
else
	lfail download "local $got_sha, builder ${want_sha:-missing}"
fi
if python3 manifest.py digest "$OUT" | tee -a "$REPORT"; then
	lpass local-digest "entries_sha256 recomputed here matches"
else
	lfail local-digest "entries_sha256 does not match the entries"
fi
src="$(python3 -c 'import gzip,json,sys; m=json.load(gzip.open(sys.argv[1])); print(m["source"]["ami_id"], m["source"]["snapshot_id"])' "$OUT")"
if [ "$src" = "$AMI $SNAP" ]; then
	lpass source "manifest names $AMI and $SNAP"
else
	lfail source "manifest names '$src', expected '$AMI $SNAP'"
fi
echo "LOCAL SUMMARY fails=$LOCAL_FAILS" | tee -a "$REPORT"
log "saved $REPORT"
[ "$LOCAL_FAILS" -eq 0 ]
