#!/usr/bin/env bash
# Replace every worker with a fresh one from the golden AMI (what the
# critical path will do one node at a time), so a test that leaves workers
# critical can be followed by another on clean nodes without rebuilding the
# cluster. The verifier drops the old instances when they leave the
# inventory and enrolls the new ones. Node objects of terminated workers
# are deleted (kubeadm has no cloud controller to do it), so they do not
# pile up as NotReady nodes.
#
# Usage: ./replace-workers.sh
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3

REGION="$(region)"
aws_ready
ASG="$(terraform -chdir=../cluster output -raw workers_asg)"
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
CPID="$(terraform -chdir=../cluster output -raw controlplane_id)"
# shellcheck disable=SC2016
mapfile -t OLD < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
WANT="$(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].DesiredCapacity' --output text)"
for id in "${OLD[@]}"; do
	log "terminating $id (the group launches a replacement)"
	aws autoscaling terminate-instance-in-auto-scaling-group --region "$REGION" --instance-id "$id" \
		--no-should-decrement-desired-capacity >/dev/null
done
aws ec2 wait instance-terminated --region "$REGION" --instance-ids "${OLD[@]}"
# Delete the Node objects of every worker whose instance is gone (these and
# any left from earlier runs).
K='kubectl --kubeconfig /etc/kubernetes/admin.conf'
nodes="$(run_ssm_json "$REGION" "$CPID" "$K get nodes -o jsonpath='{range .items[*]}{.spec.providerID}{\" \"}{.metadata.name}{\"\\n\"}{end}'" 2>/dev/null || true)"
gone=()
while read -r pid name; do
	id="${pid##*/}"
	[[ "$id" == i-* ]] || continue
	st="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$id" \
		--query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo terminated)"
	case "$st" in terminated | shutting-down | None) gone+=("$name") ;; esac
done <<<"$nodes"
if [ "${#gone[@]}" -gt 0 ]; then
	log "deleting ${#gone[@]} Node object(s) of terminated workers: ${gone[*]}"
	run_ssm_json "$REGION" "$CPID" "$K delete node ${gone[*]} --ignore-not-found" >/dev/null || log "could not delete them (not needed for the checks)"
fi
log "old workers terminated; waiting for $WANT new ones InService"
deadline=$((SECONDS + 900))
while :; do
	# shellcheck disable=SC2016
	mapfile -t NEW < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
		--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
	[ "${#NEW[@]}" -ge "$WANT" ] && break
	[ "$SECONDS" -lt "$deadline" ] || die "only ${#NEW[@]} of $WANT workers InService after 15 minutes"
	sleep 20
done
log "new workers: ${NEW[*]}; waiting for the verifier to see them healthy"
OUT="$(mktemp -d)"
FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2"
	FAILS=$((FAILS + 1))
}
# shellcheck source=lib-status.sh
. ./lib-status.sh
for w in "${NEW[@]}"; do
	check "healthy:$w" "$w" 12 'state == "verified" and tier == "healthy" and not crit and not unatt'
done
rm -rf "$OUT"
[ "$FAILS" -eq 0 ]
