#!/usr/bin/env bash
# Step 1.3 check: run after `terraform apply` from this directory.
#
#   1. AWS-side settings, through the API: worker IMDS options, ENI connection
#      tracking timeout, no public IPs, no open inbound rules, ASG lifetime.
#   2. In-cluster checks on the control plane through SSM (remote-check.sh).
#   3. On every worker: kernel module loading is locked, and the loaded
#      module list is saved (modules-<instance>.txt) for diagnosis.
#
# Usage: ./check-cluster.sh
# Env:   TF (default: terraform, falls back to tofu)
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws gzip base64

REGION="$(region)"
aws_ready
TF="${TF:-$(command -v terraform || command -v tofu || true)}"
[ -n "$TF" ] || die "terraform (or tofu) not found"

CP="$("$TF" output -raw controlplane_id 2>/dev/null || true)"
ASG="$("$TF" output -raw workers_asg 2>/dev/null || true)"
N="$("$TF" output -raw worker_count 2>/dev/null || true)"
[ -n "$CP" ] && [ -n "$ASG" ] && [ -n "$N" ] ||
	die "no cluster in the Terraform state here; run 'terraform apply' first and make sure it finished without errors"
OUT="cluster-check-$(date -u +%Y%m%d%H%M).txt"
pass=0
fail=0
result() {
	printf '%-4s %-26s %s\n' "$1" "$2" "$3" | tee -a "$OUT"
	case "$1" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; esac
}
: >"$OUT"

# --- 1. AWS-side settings --------------------------------------------------------
log "waiting for $N workers InService in $ASG"
workers=""
for _ in $(seq 1 60); do
	workers="$(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
		--query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId" --output text)"
	[ "$(echo "$workers" | wc -w)" -ge "$N" ] && break
	sleep 10
done
count="$(echo "$workers" | wc -w)"
if [ "$count" -ge "$N" ]; then result PASS asg-inservice "$count of $N workers InService"; else result FAIL asg-inservice "$count of $N workers InService"; fi

lifetime="$(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].MaxInstanceLifetime' --output text)"
if [ "$lifetime" != None ] && [ "$lifetime" -ge 86400 ]; then
	result PASS asg-max-lifetime "MaxInstanceLifetime $lifetime s"
else
	result FAIL asg-max-lifetime "MaxInstanceLifetime $lifetime"
fi

for id in $workers; do
	read -r tokens hop pubip <<<"$(aws ec2 describe-instances --region "$REGION" --instance-ids "$id" \
		--query 'Reservations[0].Instances[0].[MetadataOptions.HttpTokens,MetadataOptions.HttpPutResponseHopLimit,PublicIpAddress]' \
		--output text)"
	if [ "$tokens" = required ] && [ "$hop" = 1 ]; then
		result PASS "imds:$id" "IMDSv2 required, hop limit 1"
	else
		result FAIL "imds:$id" "HttpTokens=$tokens hop=$hop"
	fi
	if [ "$pubip" = None ]; then result PASS "no-public-ip:$id" "private only"; else result FAIL "no-public-ip:$id" "has $pubip"; fi
	tcp="$(aws ec2 describe-network-interfaces --region "$REGION" --filters "Name=attachment.instance-id,Values=$id" \
		--query 'NetworkInterfaces[0].ConnectionTrackingConfiguration.TcpEstablishedTimeout' --output text)"
	if [ "$tcp" = 60 ]; then
		result PASS "eni-tcp-timeout:$id" "tracked TCP idle timeout 60 s"
	else
		result FAIL "eni-tcp-timeout:$id" "TcpEstablishedTimeout=$tcp"
	fi
done

open="$(aws ec2 describe-security-groups --region "$REGION" \
	--filters "Name=tag:project,Values=nodetrust" "Name=ip-permission.cidr,Values=0.0.0.0/0" \
	--query 'SecurityGroups[].GroupName' --output text)"
if [ -z "$open" ]; then
	result PASS no-open-inbound "no nodetrust security group allows inbound from 0.0.0.0/0"
else
	result FAIL no-open-inbound "open inbound on: $open"
fi

# --- 2. in-cluster checks ----------------------------------------------------------
log "waiting for SSM on the control plane $CP"
wait_ssm_online "$REGION" "$CP" 10 || die "control plane $CP never came online in SSM"
log "running remote-check.sh on the control plane (can take up to 15 minutes on a fresh cluster)"
remote_ok=true
run_ssm_script "$REGION" "$CP" remote-check.sh "$N" | tee -a "$OUT" || remote_ok=false

# --- 3. module lock on every worker -------------------------------------------------
# After the network-policy test has run, each worker must still have module
# loading locked, and its loaded set is saved in case a module is missing.
for id in $workers; do
	if ! wait_ssm_online "$REGION" "$id" 5; then
		result FAIL "modules-locked:$id" "SSM not online"
		continue
	fi
	state="$(run_ssm "$REGION" "$id" "sysctl -n kernel.modules_disabled" | tr -d '[:space:]' || true)"
	if [ "$state" = 1 ]; then
		result PASS "modules-locked:$id" "kernel.modules_disabled = 1"
	else
		result FAIL "modules-locked:$id" "kernel.modules_disabled = ${state:-unknown}"
	fi
	mods="modules-$id.txt"
	run_ssm "$REGION" "$id" "lsmod | awk 'NR>1 {print \$1}' | sort" >"$mods" || true
	result INFO "module-list:$id" "$(wc -l <"$mods") modules loaded, saved to $mods"
done

log "saved $OUT"
echo "LOCAL SUMMARY pass=$pass fail=$fail" | tee -a "$OUT"
[ "$fail" -eq 0 ] && $remote_ok
