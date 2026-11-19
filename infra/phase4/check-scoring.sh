#!/usr/bin/env bash
# Step 4.4 checks on the live cluster: the trust engine (critical findings,
# weighted score, tiers, drift) and the evidence rules, against NitroTPM.
# Run on a fresh cluster right after deploy-verifier.sh (not after
# check-verifier.sh, which leaves worker 1 at warning).
#
#   1. both workers healthy, score 100
#   2. verifier outage: the verifier host drops its own connections to the
#      agents for 90 s; every node fails at once, so nothing is counted
#      (blueprint 8.4): no unattested, no critical
#   3. A8 on worker 1: a system binary changed and run -> 90, warning,
#      drift isolated
#   4. worker 2: containerd config changed and read -> 85, warning, drift
#      sudden (one runtime-config file empties that component)
#   5. worker 1 rebooted: reboot event, no critical, the mismatch stays
#      (score 90, warning) although the new boot's IMA log is clean
#   6. worker 2: a copy of kubelet, changed, run from /usr/local/bin ->
#      critical (critical-binary, matched by name)
#   7. worker 1: the agent is stopped -> unattested after two failed cycles,
#      critical (evidence-missing) after 2 minutes; starting it again does
#      not undo it
#   8. the verifier service restarts: scores, files and findings survive
#
# Usage: ./check-scoring.sh   (takes about 20 minutes)
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
OUT="$HERE/check-scoring-$(date +%Y%m%d%H%M)"
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

# --- 1. healthy ------------------------------------------------------------------------
for w in "$W1" "$W2"; do
	check "healthy:$w" "$w" 3 'state == "verified" and tier == "healthy" and score == 100 and not crit and not unatt'
done
if [ "$FAILS" -gt 0 ]; then
	echo "SUMMARY fails=$FAILS (stopped: the workers are not healthy to begin with)" | tee -a "$REPORT"
	exit 1
fi

# --- 2. verifier outage ---------------------------------------------------------------
log "verifier outage: dropping the verifier's connections to port 9443 for 90 s"
# The undo is scheduled before the block goes in, with absolute paths, so the
# block cannot outlive the test even if a later step fails.
on "$VID" "set -e; NFT=\$(command -v nft || true); IPT=\$(command -v iptables || true); U=nt-outage-end-\$(date +%s);
if [ -n \"\$NFT\" ]; then
  systemd-run --on-active=90 --unit \"\$U\" \"\$NFT\" delete table inet ntoutage
  \"\$NFT\" add table inet ntoutage
  \"\$NFT\" add chain inet ntoutage out '{ type filter hook output priority 0; }'
  \"\$NFT\" add rule inet ntoutage out tcp dport 9443 drop
else
  systemd-run --on-active=90 --unit \"\$U\" \"\$IPT\" -D OUTPUT -p tcp --dport 9443 -j DROP
  \"\$IPT\" -I OUTPUT -p tcp --dport 9443 -j DROP
fi
echo blocked"
check "outage-detected" "$W1" 2 'state == "outage"'
check "outage-no-action:$W1" "$W1" 3 'state == "verified" and not unatt and not crit and score == 100 and "unattested" not in events'
check "outage-no-action:$W2" "$W2" 1 'state == "verified" and not unatt and not crit and score == 100 and "unattested" not in events'

# --- 3. A8 on worker 1 ------------------------------------------------------------------
log "A8: /usr/bin/yes changed (one byte appended) and run on $W1"
on "$W1" "printf '\\0' >>/usr/bin/yes && /usr/bin/yes | head -1 >/dev/null && echo ran"
check "A8-warning" "$W1" 3 'tier == "warning" and score == 90 and "mismatch:/usr/bin/yes" in files and "drift-isolated" in events and not crit'

# --- 4. runtime config on worker 2 -------------------------------------------------------
log "runtime config: /etc/containerd/config.toml changed and read on $W2"
on "$W2" "echo '# nodetrust test' >>/etc/containerd/config.toml && cat /etc/containerd/config.toml >/dev/null && echo read"
check "runtime-config-sudden" "$W2" 3 'tier == "warning" and score == 85 and "/etc/containerd/config.toml" in files and "drift-sudden" in events and not crit'

# --- 5. reboot worker 1 -----------------------------------------------------------------
log "rebooting $W1"
aws ec2 reboot-instances --region "$REGION" --instance-ids "$W1"
sleep 30
wait_ssm_online "$REGION" "$W1" 10 || fail "reboot:$W1" "did not come back in SSM"
check "reboot-no-critical" "$W1" 6 'state == "verified" and "reboot" in events and not crit and not unatt'
check "reboot-keeps-mismatch" "$W1" 1 'tier == "warning" and score == 90 and "/usr/bin/yes" in files'

# --- 6. critical binary on worker 2 -------------------------------------------------------
log "critical: a changed copy of kubelet run from /usr/local/bin on $W2"
on "$W2" "cp /usr/bin/kubelet /usr/local/bin/kubelet && printf '\\0' >>/usr/local/bin/kubelet && /usr/local/bin/kubelet --version; echo ran"
check "critical-binary" "$W2" 3 'crit and "critical-binary:/usr/local/bin/kubelet" in finds'

# --- 7. agent stopped on worker 1 ---------------------------------------------------------
log "stopping the agent on $W1"
on "$W1" "systemctl stop nodetrust-agent && echo stopped"
check "agent-stopped-unattested" "$W1" 3 'unatt and not crit'
check "agent-stopped-critical" "$W1" 4 'crit and "evidence-missing" in finds'
on "$W1" "systemctl start nodetrust-agent && echo started"
check "agent-back-still-critical" "$W1" 3 'state == "verified" and crit and not unatt'

# --- 8. verifier restart ------------------------------------------------------------------
on "$VID" "systemctl restart nodetrust-verifier && echo restarted"
sleep 60
check "restart-keeps:$W1" "$W1" 2 'state == "verified" and crit and score == 90 and "/usr/bin/yes" in files and "evidence-missing" in finds'
check "restart-keeps:$W2" "$W2" 1 'state == "verified" and crit and score == 85 and "critical-binary" in finds'
run_ssm_json "$REGION" "$VID" "journalctl -u nodetrust-verifier --no-pager -o cat | tail -80" >"$OUT/journal.txt" || true

echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT"
[ "$FAILS" -eq 0 ]
