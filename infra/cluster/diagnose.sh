#!/usr/bin/env bash
# Collect read-only diagnostics from the control plane and every worker
# through SSM, into diag-<time>.txt. Run from this directory while the
# cluster is up.
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
[ -n "$CP" ] && [ -n "$ASG" ] || die "no cluster in the Terraform state here"

OUT="diag-$(date -u +%Y%m%d%H%M).txt"
{
	echo "===== control plane $CP"
	run_ssm_script "$REGION" "$CP" diag-cp.sh || true
	for id in $(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
		--query "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId" --output text); do
		echo "===== worker $id"
		run_ssm_script "$REGION" "$id" diag-worker.sh || true
	done
} | tee "$OUT"
log "saved $OUT"
