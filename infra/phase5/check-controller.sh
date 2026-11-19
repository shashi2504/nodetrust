#!/usr/bin/env bash
# The Phase 5 gate (blueprint 11): dry-run logs match the expected actions
# for every scenario, then one live quarantine of a test node succeeds end
# to end. Run on fresh workers after deploy-controller.sh. The script reads
# the controller's mode from its status and runs the matching checks.
#
# Dry run (DRY_RUN=1 ./deploy-controller.sh):
#   1. healthy workers: "would remove trust taints" (the join taint), and
#      the nodes really keep it
#   2. unknown binary on worker 2 (warning 90): "would trust taints
#      warning:PreferNoSchedule"
#   3. a fake kubelet run on worker 1 (critical): "would trust taints
#      critical:NoExecute", "would cordon", and the circuit breaker hold
#      (1 critical node of 2 workers is over 30%); after "controller
#      approve": "would isolate", "would snapshot", "would replace", "would
#      release workloads"
#   4. nothing changed: taints, cordon, security groups, network ACL,
#      snapshots and the Auto Scaling group are as before
#   5. the cluster admin cannot change a trust taint (admission policy)
#
# Live (DRY_RUN=0 ./deploy-controller.sh, fresh workers):
#   1. both workers lose the unattested join taint
#   2. unknown binary on worker 2: taint warning:PreferNoSchedule
#   3. fake kubelet on worker 1: critical taint and cordon, held by the
#      circuit breaker; the control plane still reaches its kubelet
#   4. approve: quarantine group on its ENI, ACL denies both ways, evidence
#      snapshots, detached from the group, Node object deleted; the control
#      plane no longer reaches it; the step times are reported
#   5. "controller terminate" removes the quarantined instance; the
#      snapshots stay
#   6. the group's replacement joins, is verified and loses its join taint
#
# Usage: ./check-controller.sh   (dry run: about 8 minutes; live: about 20)
# shellcheck disable=SC2015 # "check && pass || fail": pass never fails
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3

REGION="$(region)"
aws_ready
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
CPID="$(terraform -chdir=../cluster output -raw controlplane_id)"
ASG="$(terraform -chdir=../cluster output -raw workers_asg)"
SG="$(terraform -chdir=../cluster output -raw quarantine_sg_id)"
NACL="$(terraform -chdir=../cluster output -raw quarantine_nacl_id)"
OUT="$HERE/check-controller-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
REPORT="$OUT/report.txt"
FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2" | tee -a "$REPORT"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2" | tee -a "$REPORT"
	FAILS=$((FAILS + 1))
}
# shellcheck source=../phase4/lib-status.sh
. ../phase4/lib-status.sh

K='kubectl --kubeconfig /etc/kubernetes/admin.conf'
cp_run() { run_ssm_json "$REGION" "$CPID" "$1" 2>&1 || true; }

# ctl_status: the controller's status.json, saved to $OUT/ctl.json
ctl_status() {
	cp_run "cat /var/lib/nodetrust-controller/status.json" | sed -n '/^{/,$p' >"$OUT/ctl.json"
	cp "$OUT/ctl.json" "$OUT/ctl-$(date +%H%M%S).json" 2>/dev/null || true
}

# journal [instance]: the controller's log since its last start (this
# deployment), only the lines about one instance when given (SSM returns at
# most 24000 characters)
journal() {
	local f=""
	[ -n "${1:-}" ] && f="| grep -F '$1: '"
	cp_run "journalctl --no-pager -o cat _SYSTEMD_INVOCATION_ID=\$(systemctl show -p InvocationID --value nodetrust-controller) $f | tail -150" >"$OUT/journal.txt"
}

# nodes_line: one line per node, "providerID|name|key:effect,...|unschedulable".
# (Not -o json: SSM returns at most 24000 characters of output, and the node
# list in JSON is longer than that.)
NODES_JP='{range .items[*]}{.spec.providerID}{"|"}{.metadata.name}{"|"}{range .spec.taints[*]}{.key}:{.effect},{end}{"|"}{.spec.unschedulable}{"\n"}{end}'
nodes_lines() { cp_run "$K get nodes -o jsonpath='$NODES_JP'" | grep '|' >"$OUT/nodes.txt" || true; }

# taints <instance>: the Node's trust taints "taint:effect,..." plus
# "cordoned", "none", or "gone"
taints() {
	nodes_lines
	python3 - "$OUT/nodes.txt" "$1" <<'PY_EOF'
import sys
lines = [l.rstrip("\n").split("|") for l in open(sys.argv[1]) if l.count("|") >= 3]
if not lines:
    print("unreadable"); sys.exit()
for pid, name, taints, unsched in lines:
    if pid.endswith("/" + sys.argv[2]):
        # only the trust taints (cordon adds node.kubernetes.io/unschedulable)
        t = [x.replace("trust.k8s-attest.io/", "") for x in taints.split(",") if x.startswith("trust.k8s-attest.io/")]
        if unsched == "true":
            t.append("cordoned")
        print(",".join(t) or "none"); break
else:
    print("gone")
PY_EOF
}

# until_true <name> <minutes> <command...>: PASS when the command succeeds
until_true() {
	local name="$1" deadline=$((SECONDS + $2 * 60))
	shift 2
	while :; do
		if "$@" >"$OUT/last.txt" 2>&1; then
			pass "$name" "$(tr '\n' ' ' <"$OUT/last.txt" | cut -c1-220)"
			return 0
		fi
		[ "$SECONDS" -lt "$deadline" ] || break
		sleep 10
	done
	fail "$name" "$(tr '\n' ' ' <"$OUT/last.txt" | cut -c1-220)"
	return 1
}

# logged <instance> <text...>: every text appears in the log for the instance
logged() {
	local id="$1"
	shift
	journal "$id"
	local t
	for t in "$@"; do
		grep -F "$id: " "$OUT/journal.txt" | grep -qF "$t" || {
			echo "missing: $t"
			return 1
		}
	done
	grep -F "$id: " "$OUT/journal.txt" | tail -12
}

taint_is() { # taint_is <instance> <want>
	local t
	t="$(taints "$1")"
	echo "$1: $t"
	[ "$t" = "$2" ]
}

# aws_view <instance>: groups, ACL denies, snapshots, group membership
aws_view() {
	local ip groups denies snaps asg
	ip="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$1" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"
	groups="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$1" --query 'Reservations[0].Instances[0].NetworkInterfaces[].Groups[].GroupId' --output text | tr '\t' ' ')"
	denies="$(aws ec2 describe-network-acls --region "$REGION" --network-acl-ids "$NACL" \
		--query "NetworkAcls[0].Entries[?CidrBlock=='$ip/32' && RuleAction=='deny'].[Egress]" --output text | tr '\n' ' ')"
	snaps="$(aws ec2 describe-snapshots --region "$REGION" --owner-ids self --filters "Name=tag:nodetrust:instance,Values=$1" \
		--query 'Snapshots[].SnapshotId' --output text | tr '\t' ' ')"
	asg="$(aws autoscaling describe-auto-scaling-instances --region "$REGION" --instance-ids "$1" \
		--query 'AutoScalingInstances[0].AutoScalingGroupName' --output text)"
	echo "ip=$ip groups=[$groups] acl-denies=[$denies] snapshots=[$snaps] asg=$asg"
}

# shellcheck disable=SC2016
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -ge 2 ] || die "need two InService workers"
W1="${WORKERS[0]}"
W2="${WORKERS[1]}"
wait_ssm_online "$REGION" "$CPID" 5 || die "control plane not online in SSM"
ctl_status
DRY="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["dry_run"]).lower())' "$OUT/ctl.json" 2>/dev/null)" ||
	die "cannot read the controller's status; is it deployed? $(head -c 300 "$OUT/ctl.json")"
log "controller dry_run=$DRY; worker 1 $W1, worker 2 $W2"
for w in "$W1" "$W2"; do
	check "verifier-healthy:$w" "$w" 5 'state == "verified" and tier == "healthy" and not crit and not unatt'
done
[ "$FAILS" -eq 0 ] || die "workers not healthy at the start; replace them first"
# no approval left from an earlier run may skip the circuit breaker
cp_run "rm -f /var/lib/nodetrust-controller/approve/$W1 /var/lib/nodetrust-controller/approve/$W2" >/dev/null
aws_view "$W1" >"$OUT/aws-before.txt"
log "worker 1 before: $(cat "$OUT/aws-before.txt")"

warning_w2() {
	wait_ssm_online "$REGION" "$W2" 5 || die "$W2 not online in SSM"
	run_ssm_json "$REGION" "$W2" "cp /usr/bin/true /usr/local/bin/nt-controller-test && /usr/local/bin/nt-controller-test && echo ran" >/dev/null
	check "verifier-warning:$W2" "$W2" 3 'tier == "warning" and score == 90'
}
critical_w1() {
	wait_ssm_online "$REGION" "$W1" 5 || die "$W1 not online in SSM"
	# basename kubelet: a critical binary that is not the reference one
	run_ssm_json "$REGION" "$W1" "cp /usr/bin/true /usr/local/bin/kubelet && /usr/local/bin/kubelet && echo ran" >/dev/null
	T_INJECT=$SECONDS
	check "verifier-critical:$W1" "$W1" 3 'crit and "critical-binary" in finds'
}

if [ "$DRY" = true ]; then
	# --- dry run -------------------------------------------------------------------------
	until_true "dry-healthy" 2 logged "$W1" "dry-run: would trust taints removed"
	until_true "dry-keeps-join-taint" 1 taint_is "$W1" "unattested:NoSchedule"
	warning_w2
	until_true "dry-warning" 2 logged "$W2" "dry-run: would trust taints warning:PreferNoSchedule"
	critical_w1
	until_true "dry-critical" 2 logged "$W1" "critical: critical-binary /usr/local/bin/kubelet" \
		"dry-run: would trust taints critical:NoExecute" "dry-run: would cordon" "dry-run: would hold isolation: circuit breaker open"
	cp_run "nodetrust-controller approve -instance $W1" >"$OUT/approve.txt"
	until_true "dry-approved-plan" 2 logged "$W1" "dry-run: would isolate: quarantine security group and NACL deny" \
		"dry-run: would snapshot the EBS volumes" "dry-run: would replace: detach from the Auto Scaling group" \
		"dry-run: would release workloads: delete the Node object"
	aws_view "$W1" >"$OUT/aws-after.txt"
	if cmp -s "$OUT/aws-before.txt" "$OUT/aws-after.txt" && [ "$(taints "$W1")" = "unattested:NoSchedule" ]; then
		pass "dry-changed-nothing" "$(cat "$OUT/aws-after.txt"); node taints unattested:NoSchedule"
	else
		fail "dry-changed-nothing" "before: $(cat "$OUT/aws-before.txt") after: $(cat "$OUT/aws-after.txt") taints: $(taints "$W1")"
	fi
	cp_run "rm -f /var/lib/nodetrust-controller/approve/$W1" >/dev/null
else
	# --- live ----------------------------------------------------------------------------
	until_true "live-join-taint-removed:$W1" 3 taint_is "$W1" "none"
	until_true "live-join-taint-removed:$W2" 1 taint_is "$W2" "none"
	warning_w2
	until_true "live-warning-taint" 2 taint_is "$W2" "warning:PreferNoSchedule"
	W1IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$W1" --query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"
	reach() { cp_run "timeout 4 bash -c '</dev/tcp/$W1IP/10250' && echo reachable || echo unreachable" | grep -m1 -xE 'reachable|unreachable'; }
	cut_off() {
		local r
		r="$(reach)"
		echo "control plane -> $W1IP:10250: $r"
		[ "$r" = unreachable ]
	}
	[ "$(reach)" = reachable ] && pass "reach-before" "control plane reaches $W1IP:10250" || fail "reach-before" "$(reach)"
	critical_w1
	until_true "live-critical-taint" 2 taint_is "$W1" "critical:NoExecute,cordoned"
	pass "time-to-cordon" "$((SECONDS - T_INJECT)) s from the fake kubelet run to the critical taint (verifier challenge + controller round)"
	until_true "live-breaker-held" 1 logged "$W1" "hold isolation: circuit breaker open"
	aws_view "$W1" >"$OUT/aws-held.txt"
	cmp -s "$OUT/aws-before.txt" "$OUT/aws-held.txt" && pass "held-no-aws-change" "$(cat "$OUT/aws-held.txt")" ||
		fail "held-no-aws-change" "$(cat "$OUT/aws-held.txt")"
	cp_run "nodetrust-controller approve -instance $W1" >"$OUT/approve.txt"
	until_true "live-contained" 2 logged "$W1" "operator approved containment" "isolate: quarantine security group and NACL deny (done" \
		"snapshot the EBS volumes: snap-" "replace: detach from the Auto Scaling group (desired capacity kept) (done" \
		"release workloads: delete the Node object (done"
	aws_view "$W1" >"$OUT/aws-after.txt"
	v="$(cat "$OUT/aws-after.txt")"
	[[ "$v" == *"groups=[$SG]"* ]] && pass "quarantine-group" "$v" || fail "quarantine-group" "$v"
	[[ "$v" == *"acl-denies=[False True ]"* || "$v" == *"acl-denies=[True False ]"* ]] && pass "acl-denies" "in and out for $W1IP/32" || fail "acl-denies" "$v"
	[[ "$v" == *"snapshots=[snap-"* ]] && pass "evidence-snapshots" "$v" || fail "evidence-snapshots" "$v"
	[[ "$v" == *"asg=None"* ]] && pass "detached" "not in $ASG any more" || fail "detached" "$v"
	until_true "node-deleted" 1 taint_is "$W1" "gone"
	until_true "reach-after" 1 cut_off
	grep -F "$W1: " "$OUT/journal.txt" | grep "(done in" | sed 's/^/    /' | tee -a "$REPORT"
	# Terminate the quarantined instance before waiting for the replacement:
	# with an account limit of 8 vCPUs (control plane, verifier and two
	# workers) the group cannot launch while the quarantined node still runs.
	cp_run "nodetrust-controller terminate -instance $W1 -yes" | tee "$OUT/terminate.txt" | sed 's/^/    /'
	until_true "terminated" 3 bash -c "aws ec2 describe-instances --region $REGION --instance-ids $W1 --query 'Reservations[0].Instances[0].State.Name' --output text | grep -E 'shutting-down|terminated'"
	snaps="$(aws ec2 describe-snapshots --region "$REGION" --owner-ids self --filters "Name=tag:nodetrust:instance,Values=$W1" --query 'Snapshots[].SnapshotId' --output text)"
	[ -n "$snaps" ] && pass "evidence-kept" "$snaps" || fail "evidence-kept" "no snapshots"
	echo "delete the evidence when done: for s in $snaps; do aws ec2 delete-snapshot --region $REGION --snapshot-id \$s; done" | tee -a "$REPORT"
	# the replacement
	new_worker() {
		local ids n
		# shellcheck disable=SC2016
		ids="$(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
			--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text)"
		for n in $ids; do [ "$n" != "$W2" ] && echo "$n" && return 0; done
		return 1
	}
	until_true "replacement-launched" 10 new_worker
	W3="$(new_worker || true)"
	if [ -n "$W3" ]; then
		check "replacement-verified:$W3" "$W3" 12 'state == "verified" and tier == "healthy" and not crit and not unatt'
		until_true "replacement-join-taint-removed" 3 taint_is "$W3" "none"
	fi
fi

# --- either mode: nobody else writes trust taints ----------------------------------------
nodes_lines
N2="$(awk -F'|' -v w="$W2" '$1 ~ ("/" w "$") { print $2 }' "$OUT/nodes.txt")"
out="$(cp_run "$K taint node $N2 trust.k8s-attest.io/fake=x:NoSchedule")"
grep -q "only the nodetrust controller" <<<"$out" && pass "admin-taint-denied" "denied by the nodetrust-taints admission policy" ||
	fail "admin-taint-denied" "$(tr '\n' ' ' <<<"$out" | cut -c1-200)"

ctl_status
journal
echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT (journal.txt has the controller log)"
[ "$FAILS" -eq 0 ]
