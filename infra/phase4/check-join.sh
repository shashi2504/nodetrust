#!/usr/bin/env bash
# Step 4.6 checks on the live cluster: join-time files (blueprint 10.4).
# Run on fresh workers after join-reference.sh and deploy-verifier.sh.
#
#   1. both workers healthy with the narrowed runtime policy: every join
#      file they measured matches the join reference or the fleet
#   2. A10 on worker 1: kubelet config and containerd config changed, both
#      services restarted in one cycle -> 72.5, degraded, drift sudden
#   3. worker 2: kubeadm-flags.env changed and kubelet restarted (systemd
#      reads it as root) -> Kubernetes config -12.5, 87.5, warning
#   4. worker 2: a CNI plugin Calico installed is changed and read -> not
#      the hash in the join reference, system binaries -10, 77.5
#
# Both workers end degraded or warning; replace them afterwards.
#
# Usage: ./check-join.sh   (takes about 10 minutes)
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
OUT="$HERE/check-join-$(date +%Y%m%d%H%M)"
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

on() { # on <instance> <command>: run as root over SSM; stop with the output if it fails
	local out
	wait_ssm_online "$REGION" "$1" 5 || die "$1 not online in SSM"
	if ! out="$(run_ssm_json "$REGION" "$1" "$2" 2>&1)"; then
		printf '%s\n' "$out" >>"$OUT/commands.txt"
		fail "command:$1" "$(printf '%s' "$out" | tail -5 | tr '\n' ' ')"
		echo "SUMMARY fails=$FAILS (stopped: a test command failed on $1, see $OUT/commands.txt)" | tee -a "$REPORT"
		exit 1
	fi
	printf '%s\n' "$out" >>"$OUT/commands.txt"
}

# shellcheck disable=SC2016
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -ge 2 ] || die "need two InService workers"
W1="${WORKERS[0]}"
W2="${WORKERS[1]}"
log "worker 1 $W1, worker 2 $W2"

# --- 1. clean nodes ---------------------------------------------------------------------
for w in "$W1" "$W2"; do
	check "healthy:$w" "$w" 5 'state == "verified" and tier == "healthy" and score == 100 and not crit and not unatt and num("cycles") >= 3'
done
run_ssm_json "$REGION" "$VID" "cat /var/lib/nodetrust-verifier/consensus.json" >"$OUT/consensus.json" || true
log "consensus: $(python3 -c 'import json,sys; v=json.load(open(sys.argv[1]))["votes"]; print(sum(len(p) for p in v.values()), "paths")' "$OUT/consensus.json" 2>/dev/null || echo unreadable)"
if [ "$FAILS" -gt 0 ]; then
	echo "SUMMARY fails=$FAILS (stopped: the workers are not healthy to begin with)" | tee -a "$REPORT"
	exit 1
fi

# --- 2. A10 on worker 1 -----------------------------------------------------------------
log "A10: kubelet config and containerd config changed on $W1, both restarted"
on "$W1" "echo '# nodetrust test' >>/var/lib/kubelet/config.yaml && echo '# nodetrust test' >>/etc/containerd/config.toml && systemctl restart containerd kubelet && echo restarted"
check "A10-degraded" "$W1" 3 'tier == "degraded" and score == 72.5 and "/var/lib/kubelet/config.yaml" in files and "/etc/containerd/config.toml" in files and "drift-sudden" in events and not crit'

# --- 3. kubeadm flags on worker 2 ---------------------------------------------------------
log "kubeadm-flags.env changed on $W2, kubelet restarted"
# Rewritten in place: sed -i would leave a temp file in /var/lib/kubelet that
# is measured too.
on "$W2" "f=/var/lib/kubelet/kubeadm-flags.env; c=\$(cat \$f); echo \"\${c%?} --v=2\\\"\" >\$f && cat \$f && systemctl restart kubelet && echo restarted"
check "kubeadm-flags-warning" "$W2" 3 'tier == "warning" and score == 87.5 and "/var/lib/kubelet/kubeadm-flags.env" in files and not crit'

# --- 4. a CNI plugin against the fleet --------------------------------------------------
log "a Calico CNI plugin changed and read on $W2"
on "$W2" "P=/opt/cni/bin/loopback; [ -f \$P ] || P=\$(ls /opt/cni/bin/* | head -1); printf '\\0' >>\$P && cat \$P >/dev/null && echo \$P"
check "cni-consensus" "$W2" 3 'score == 77.5 and "/opt/cni/bin/" in files and not crit'

run_ssm_json "$REGION" "$VID" "cat /var/lib/nodetrust-verifier/consensus.json; journalctl -u nodetrust-verifier --no-pager -o cat | tail -60" >"$OUT/journal.txt" || true
echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT; replace the workers before other checks"
[ "$FAILS" -eq 0 ]
