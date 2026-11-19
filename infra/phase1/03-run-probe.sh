#!/usr/bin/env bash
# Run probe.sh on the instance through SSM, then compare the EK the
# node reports with the EK the EC2 API reports for that instance.
#
# Usage: [PROBE_MODE=golden] ./03-run-probe.sh <instance-id>
# PROBE_MODE=golden adds the step 1.2 checks for the golden AMI.
# Saves the full output to probe-<instance-id>.txt in this directory.
set -euo pipefail
cd "$(dirname "$0")"
. ./lib.sh
need aws

ID="${1:-}"
[ -n "$ID" ] || die "usage: $0 <instance-id>"
REGION="$(region)"
aws_ready
OUT="probe-$ID.txt"

run_ssm() { # run_ssm <shell command>: prints stdout, returns the command's status
	local cid status
	cid="$(aws ssm send-command --region "$REGION" --instance-ids "$ID" \
		--document-name AWS-RunShellScript \
		--parameters "commands=[\"$1\"]" \
		--query Command.CommandId --output text)"
	aws ssm wait command-executed --region "$REGION" --command-id "$cid" --instance-id "$ID" 2>/dev/null || true
	status="$(aws ssm get-command-invocation --region "$REGION" --command-id "$cid" --instance-id "$ID" \
		--query Status --output text)"
	aws ssm get-command-invocation --region "$REGION" --command-id "$cid" --instance-id "$ID" \
		--query StandardOutputContent --output text
	[ "$status" = Success ]
}

log "waiting for the SSM agent and the post-reboot boot with IMA on (up to 10 minutes)"
for _ in $(seq 1 60); do
	ping="$(aws ssm describe-instance-information --region "$REGION" \
		--filters "Key=InstanceIds,Values=$ID" \
		--query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null || true)"
	if [ "$ping" = Online ] &&
		run_ssm "test -f /opt/nodetrust/.firstboot-done && grep -q ima_template=ima-ng /proc/cmdline && echo ready" 2>/dev/null | grep -q ready; then
		break
	fi
	sleep 10
done

case "${PROBE_MODE:-base}" in
base) PROBE_ARGS="" ;;
golden) PROBE_ARGS="--golden" ;;
*) die "PROBE_MODE must be base or golden" ;;
esac
log "running probe.sh ${PROBE_ARGS}"
probe_ok=true
run_ssm "bash /opt/nodetrust/probe.sh ${PROBE_ARGS}" >"$OUT" || probe_ok=false
grep -v '^EK_RSA_DER_B64=' "$OUT" >&2

log "comparing the node's EK with the EC2 API"
node_ek="$(sed -n 's/^EK_RSA_DER_B64=//p' "$OUT" | tr -d '\r\n')"
api_ek="$(aws ec2 get-instance-tpm-ek-pub --region "$REGION" --instance-id "$ID" \
	--key-type rsa-2048 --key-format der --query KeyValue --output text | tr -d '\r\n')"
if [ -n "$node_ek" ] && [ "$node_ek" = "$api_ek" ]; then
	line="PASS ek-matches-ec2-api       RSA EK from the node equals GetInstanceTpmEkPub"
	ek_ok=true
else
	line="FAIL ek-matches-ec2-api       node=${node_ek:0:24}... api=${api_ek:0:24}..."
	ek_ok=false
fi
echo "$line" | tee -a "$OUT" >&2

log "saved $OUT"
$probe_ok && $ek_ok
