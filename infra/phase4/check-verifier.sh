#!/usr/bin/env bash
# Step 4.2 checks against the running verifier service (deploy-verifier.sh first).
#
#   1. every worker of the Auto Scaling group is enrolled and healthy
#   2. an instance from a stock Ubuntu AMI, tagged like a worker, is refused
#      and never enrolled (the AMI comes from EC2, so tags do not help it)
#   3. a binary not in the manifest runs on worker 1: the next round lists
#      the file and worker 1 drops to warning (score 90, blueprint A9);
#      worker 2 stays healthy
#   4. the service restarts: the enrollments are kept (no new enrollment)
#
# Worker 1 is left at warning; replace it (or destroy the cluster) afterwards.
#
# Usage: ./check-verifier.sh
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3

REGION="$(region)"
aws_ready
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
ASG="$(terraform -chdir=../cluster output -raw workers_asg)"
OUT="$HERE/check-verifier-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
REPORT="$OUT/report.txt"
FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2" | tee -a "$REPORT"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2" | tee -a "$REPORT"
	FAILS=$((FAILS + 1))
}

# shellcheck source=lib-status.sh
. ./lib-status.sh

# shellcheck disable=SC2016
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -ge 2 ] || die "need two InService workers"
W1="${WORKERS[0]}"
W2="${WORKERS[1]}"

# --- 1. workers healthy ---------------------------------------------------------------
for w in "${WORKERS[@]}"; do
	check "healthy:$w" "$w" 3 'state == "verified" and tier == "healthy" and score == 100 and not crit and not unatt'
done

# --- 2. a stock AMI tagged as a worker ------------------------------------------------
STOCK="$(aws ssm get-parameter --region "$REGION" --name /aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id --query Parameter.Value --output text)"
SUBNET="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$W1" --query 'Reservations[0].Instances[0].SubnetId' --output text)"
SG="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$W1" --query 'Reservations[0].Instances[0].SecurityGroups[0].GroupId' --output text)"
# A spot instance: it counts against the spot vCPU quota, not the on-demand
# one the cluster already fills (8 vCPUs on a new account).
if ROGUE="$(aws ec2 run-instances --region "$REGION" --image-id "$STOCK" --instance-type t3.micro \
	--instance-market-options 'MarketType=spot,SpotOptions={SpotInstanceType=one-time,InstanceInterruptionBehavior=terminate}' \
	--subnet-id "$SUBNET" --security-group-ids "$SG" --metadata-options HttpTokens=required \
	--tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=nodetrust-rogue},{Key=role,Value=worker},{Key=project,Value=nodetrust}]' \
	--query 'Instances[0].InstanceId' --output text 2>"$OUT/rogue-error.txt")"; then
	trap 'aws ec2 terminate-instances --region "$REGION" --instance-ids "$ROGUE" >/dev/null 2>&1 || true' EXIT
	log "rogue instance $ROGUE from $STOCK (stock Ubuntu), tagged role=worker"
	aws ec2 wait instance-running --region "$REGION" --instance-ids "$ROGUE"
	check "refuse-stock-ami" "$ROGUE" 3 'state == "refused" and tier == "-"' 
	run_ssm_json "$REGION" "$VID" "ls /var/lib/nodetrust-verifier/enrolled/" >"$OUT/enrolled.txt" || true
	if grep -q "$ROGUE" "$OUT/enrolled.txt"; then fail "rogue-not-enrolled" "an enrollment record exists"; else pass "rogue-not-enrolled" "no enrollment record for $ROGUE"; fi
	aws ec2 terminate-instances --region "$REGION" --instance-ids "$ROGUE" >/dev/null
else
	fail "refuse-stock-ami" "could not launch the test instance: $(tr '\n' ' ' <"$OUT/rogue-error.txt" | cut -c1-300)"
fi

# --- 3. an unknown binary on worker 1 ------------------------------------------------
wait_ssm_online "$REGION" "$W1" 5 || die "$W1 not online in SSM"
run_ssm_json "$REGION" "$W1" "cp /usr/bin/true /root/nt-unknown-binary && /root/nt-unknown-binary && echo ran" >"$OUT/tamper.txt" ||
	die "could not run the test binary: $(cat "$OUT/tamper.txt")"
check "detect-unknown-binary" "$W1" 3 'tier == "warning" and score == 90 and "/root/nt-unknown-binary" in files and not crit'
check "other-worker-healthy" "$W2" 1 'tier == "healthy" and score == 100 and not crit'

# --- 4. restart keeps the enrollments ------------------------------------------------
run_ssm_json "$REGION" "$VID" "systemctl restart nodetrust-verifier; sleep 75; journalctl -u nodetrust-verifier --since '-80s' --no-pager -o cat" >"$OUT/restart.txt" || true
if grep -q "enrolled (EK" "$OUT/restart.txt"; then
	fail "restart-keeps-enrollment" "the service enrolled again after a restart"
elif grep -q "round done" "$OUT/restart.txt"; then
	pass "restart-keeps-enrollment" "$(grep 'round done' "$OUT/restart.txt" | tail -1)"
else
	fail "restart-keeps-enrollment" "no round after the restart: $(tail -3 "$OUT/restart.txt" | tr '\n' ' ')"
fi

echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT; worker $W1 ran an unknown binary and stays at warning"
[ "$FAILS" -eq 0 ]
