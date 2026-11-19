#!/usr/bin/env bash
# Step 4.1: check every worker's boot event log against the boot policy and
# the AMI's signed manifest.
#
# Run infra/phase3/attest-cluster.sh first: its attest-node runs leave, on
# the verifier host, eventlog.bin and pcrs.txt for each worker, both from a
# quote whose signature, nonce and PCR digest were verified (and the log was
# already replayed to those PCRs there).
#
#   1. download and verify the AMI's manifest chain (signature, AMI, Rekor)
#   2. fetch each worker's eventlog.bin and pcrs.txt from the verifier host
#   3. if boot-policy.json has no entry for the AMI: write one from the first
#      worker's log (boot-reference) and stop, so it is reviewed before use
#   4. check-boot every worker (root volume from EC2)
#   5. negative check: worker 1's log against another instance's root volume
#
# Usage: ./check-boot.sh   (with infra/cluster applied and attest-cluster.sh run)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform go base64 gzip sha256sum

REGION="$(region)"
aws_ready
BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket)"
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
ASG="$(terraform -chdir=../cluster output -raw workers_asg)"
SIGNING_PIN="$REPO/infra/trust/manifest-signing-key.pem"
REKOR_PIN="$REPO/infra/trust/rekor-public-key.pem"
[ -f "$SIGNING_PIN" ] && [ -f "$REKOR_PIN" ] || die "pinned keys missing in infra/trust"
POLICY="$HERE/boot-policy.json"
OUT="$HERE/check-boot-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
REPORT="$OUT/report.txt"

FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2" | tee -a "$REPORT"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2" | tee -a "$REPORT"
	FAILS=$((FAILS + 1))
}

# shellcheck disable=SC2016 # backticks are JMESPath literals, not shell
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -gt 0 ] || die "no InService workers in $ASG"
wait_ssm_online "$REGION" "$VID" 10 || die "verifier host $VID is not online in SSM"

(cd "$REPO" && go build -trimpath -o "$OUT/verifier" ./cmd/verifier)
V="$OUT/verifier"

# --- 1. trusted manifest (all workers come from one launch template) ----------------
AMI="$(aws ec2 describe-instances --region "$REGION" --instance-ids "${WORKERS[0]}" \
	--query 'Reservations[0].Instances[0].ImageId' --output text)"
[[ "$AMI" == ami-* ]] || die "could not read the AMI of ${WORKERS[0]}"
for f in statement.json statement.sig rekor-entry.json; do
	aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/signed/$AMI/$f" "$OUT/$f" ||
		die "no $f for $AMI in the bucket; build, sign and log its manifest first"
done
aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/manifests/$AMI/manifest.json.gz" "$OUT/manifest.json.gz"
TRUST=(-public-key "$SIGNING_PIN" -statement "$OUT/statement.json" -signature "$OUT/statement.sig"
	-manifest "$OUT/manifest.json.gz" -ami "$AMI" -rekor-entry "$OUT/rekor-entry.json" -rekor-key "$REKOR_PIN")
"$V" verify-manifest "${TRUST[@]}" >"$OUT/manifest-check.txt" 2>&1 ||
	die "the manifest for $AMI does not verify: $(cat "$OUT/manifest-check.txt")"
pass trusted-manifest "$AMI: signature, AMI binding, manifest hashes and Rekor entry verify"
# grep -c reads to the end: grep -q would stop at the first match, gzip would
# die of SIGPIPE, and pipefail would turn the match into a failure.
if [ "$(gzip -dc "$OUT/manifest.json.gz" | grep -c '"authenticode_sha256"')" -gt 0 ]; then
	pass manifest-authenticode "manifest has Authenticode hashes for the EFI images"
else
	die "the manifest for $AMI has no Authenticode hashes (built by manifest.py/1); rebuild it with build-manifest.sh"
fi

# --- 2. event logs from the verifier host --------------------------------------------
W=/root/nt-verifier
fetch() { # fetch <remote file> <local file>: gzip, base64 in chunks, sha256 checked
	local info want size k chunk=15000
	info="$(run_ssm_json "$REGION" "$VID" "set -e; gzip -c $1 >$1.gz; sha256sum $1.gz; stat -c %s $1.gz")" || return 1
	want="$(awk '{ if (NF == 2) print $1 }' <<<"$info" | head -1)"
	size="$(grep -E '^[0-9]+$' <<<"$info" | tail -1)"
	[[ "$size" =~ ^[0-9]+$ ]] && [ -n "$want" ] || return 1
	: >"$2.gz"
	for ((k = 0; k * chunk < size; k++)); do
		run_ssm_json "$REGION" "$VID" "dd if=$1.gz bs=$chunk skip=$k count=1 status=none | base64 -w0" |
			tr -d '[:space:]' | base64 -d >>"$2.gz"
	done
	[ "$(sha256sum "$2.gz" | cut -d' ' -f1)" = "$want" ] && gzip -df "$2.gz"
}
declare -A VOL
for IID in "${WORKERS[@]}"; do
	mkdir -p "$OUT/$IID"
	if fetch "$W/$IID/eventlog.bin" "$OUT/$IID/eventlog.bin" && fetch "$W/$IID/pcrs.txt" "$OUT/$IID/pcrs.txt"; then
		pass "fetched:$IID" "eventlog.bin ($(stat -c %s "$OUT/$IID/eventlog.bin") bytes) and pcrs.txt from the verifier host"
	else
		die "no eventlog.bin/pcrs.txt for $IID on the verifier host; run ../phase3/attest-cluster.sh with this agent first"
	fi
	# shellcheck disable=SC2016
	read -r iami root < <(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
		--query 'Reservations[0].Instances[0].[ImageId, RootDeviceName]' --output text)
	[ "$iami" = "$AMI" ] || die "$IID runs $iami, not $AMI"
	VOL[$IID]="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
		--query "Reservations[0].Instances[0].BlockDeviceMappings[?DeviceName=='$root'].Ebs.VolumeId | [0]" --output text)"
	[[ "${VOL[$IID]}" == vol-* ]] || die "could not read the root volume of $IID"
done

# --- 3. reference ---------------------------------------------------------------------
if [ ! -f "$POLICY" ] || ! grep -q "\"$AMI\"" "$POLICY"; then
	base=()
	[ -f "$POLICY" ] && base=(-base "$POLICY")
	"$V" boot-reference -event-log "$OUT/${WORKERS[0]}/eventlog.bin" -ami "$AMI" "${base[@]}" \
		-firmware-why "NitroTPM firmware measured on ${WORKERS[0]} ($AMI), $(date -u +%Y-%m-%d)" \
		-out "$OUT/boot-policy.json" | tee -a "$REPORT"
	log "boot-policy.json has no entry for $AMI. Review $OUT/boot-policy.json"
	log "(kernel command line, GPT, Secure Boot digests, firmware value), then:"
	log "  cp $OUT/boot-policy.json $POLICY && ./check-boot.sh"
	exit 0
fi
pass boot-policy "$POLICY has $AMI"

# --- 4. check every worker -----------------------------------------------------------
for IID in "${WORKERS[@]}"; do
	if "$V" check-boot "${TRUST[@]}" -boot-policy "$POLICY" -event-log "$OUT/$IID/eventlog.bin" \
		-pcrs "$OUT/$IID/pcrs.txt" -root-volume "${VOL[$IID]}" >"$OUT/$IID/check-boot.txt" 2>&1; then
		pass "boot:$IID" "$(grep -c '^OK   boot' "$OUT/$IID/check-boot.txt") checks pass (root volume ${VOL[$IID]})"
	else
		fail "boot:$IID" "$(grep '^FAIL' "$OUT/$IID/check-boot.txt" | tr '\n' ' ' | cut -c1-500)"
	fi
done

# --- 5. negative: a log presented for another instance --------------------------------
I1="${WORKERS[0]}"
other=vol-0123456789abcdef0
[ "${#WORKERS[@]}" -gt 1 ] && other="${VOL[${WORKERS[1]}]}"
if "$V" check-boot "${TRUST[@]}" -boot-policy "$POLICY" -event-log "$OUT/$I1/eventlog.bin" \
	-pcrs "$OUT/$I1/pcrs.txt" -root-volume "$other" >"$OUT/negative.txt" 2>&1; then
	fail reject-other-volume "$I1's boot was accepted for root volume $other"
elif grep -q '^FAIL boot pcr 1 root-volume' "$OUT/negative.txt"; then
	pass reject-other-volume "$I1's boot rejected for root volume $other (PCR 1 names ${VOL[$I1]})"
else
	fail reject-other-volume "failed for another reason: $(grep '^FAIL' "$OUT/negative.txt" | head -3 | tr '\n' ' ')"
fi

echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT"
[ "$FAILS" -eq 0 ]
