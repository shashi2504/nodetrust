#!/usr/bin/env bash
# Step 4.5 checks on the live cluster: what each challenge carries besides
# the quote (blueprint 6.2, 10.2, 10.3, 10.5). Run on a fresh cluster right
# after deploy-verifier.sh.
#
#   1. both workers healthy; every challenge finds the canary in the quoted
#      log, sweeps files, audits mount namespaces; after the first cycle of
#      the boot the log comes incrementally (few new entries) and the boot
#      PCRs are compared, not re-read; healthy nodes run at the base interval
#   2. hint (10.5): an unknown binary run on worker 1 is seen within seconds,
#      well before the next timed challenge; worker 1 then runs at a shorter
#      interval (warning, recently changed)
#   3. A13 on worker 2: runc changed but never run -> critical at the next
#      sweep
#   4. A15 on worker 1: an overlay over /usr/bin in a private mount
#      namespace -> critical (mount-overlay)
#   5. canary on worker 1: the canary file made immutable, so the agent
#      cannot write it -> critical (ima-canary). This stands in for A16
#      (IMA frozen), which needs a test harness.
#
# Both workers end critical; destroy the cluster afterwards.
#
# Usage: ./check-probes.sh   (takes about 15 minutes)
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
OUT="$HERE/check-probes-$(date +%Y%m%d%H%M)"
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
	printf '%s\n' "$out"
}

# event_time <instance> <kind>: unix time of the node's last event of that kind
event_time() {
	python3 - "$OUT/status.json" "$1" "$2" <<'PY_EOF'
import json, sys, datetime
for n in json.load(open(sys.argv[1]))["nodes"]:
    if n["instance_id"] == sys.argv[2]:
        ts = [e["at"] for e in n.get("recent") or [] if e["kind"] == sys.argv[3]]
        if ts:
            print(datetime.datetime.fromisoformat(ts[-1].replace("Z", "+00:00")).timestamp())
PY_EOF
}

# shellcheck disable=SC2016
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -ge 2 ] || die "need two InService workers"
W1="${WORKERS[0]}"
W2="${WORKERS[1]}"
log "worker 1 $W1, worker 2 $W2"

# --- 1. probes on a clean node ----------------------------------------------------------
for w in "$W1" "$W2"; do
	check "healthy:$w" "$w" 3 'state == "verified" and tier == "healthy" and score == 100 and not crit and not unatt'
done
if [ "$FAILS" -gt 0 ]; then
	echo "SUMMARY fails=$FAILS (stopped: the workers are not healthy to begin with)" | tee -a "$REPORT"
	exit 1
fi
for w in "$W1" "$W2"; do
	check "probes:$w" "$w" 4 'x["canary"] == "found" and x["boot"] == "unchanged" and num("sweep") > 0 and num("mountns") > 0 and num("cycles") >= 2 and num("new") < 200'
	check "base-interval:$w" "$w" 1 'num("interval") == 60'
done

# --- 2. hint latency --------------------------------------------------------------------
log "A9 with a hint: an unknown binary run on $W1"
T0="$(on "$W1" "cp /usr/bin/true /usr/local/bin/nt-hint-test && /usr/local/bin/nt-hint-test && date +%s.%N" | tail -1)"
check "hint-detected" "$W1" 2 'tier == "warning" and "/usr/local/bin/nt-hint-test" in files'
T1="$(event_time "$W1" drift-isolated)"
if [ -n "$T1" ] && python3 -c "import sys; d=float(sys.argv[2])-float(sys.argv[1]); print(f'{d:.1f}'); sys.exit(0 if -2 < d < 15 else 1)" "$T0" "$T1" >"$OUT/hint-delay.txt"; then
	pass "hint-latency" "seen $(cat "$OUT/hint-delay.txt") s after the binary ran (base interval 60 s)"
else
	fail "hint-latency" "binary ran at $T0, drift event at ${T1:-none} ($(cat "$OUT/hint-delay.txt" 2>/dev/null))"
fi
check "shorter-interval" "$W1" 2 'num("interval") == 15'

# --- 3. A13: runc changed, never run ------------------------------------------------------
RUNC="$(on "$W2" "readlink -f \$(command -v runc)" | tail -1)"
log "A13: $RUNC changed on $W2 and not run"
on "$W2" "printf '\\0' >>$RUNC && echo changed" >/dev/null
check "A13-sweep-critical" "$W2" 3 "crit and \"critical-binary:$RUNC\" in finds"

# --- 4. A15: overlay in a private mount namespace -----------------------------------------
log "A15: overlay over /usr/bin in a private mount namespace on $W1"
on "$W1" "mkdir -p /root/ov/u /root/ov/w && systemd-run --unit nt-overlay-test unshare -m --propagation private sh -c 'mount -t overlay overlay -o lowerdir=/usr/bin,upperdir=/root/ov/u,workdir=/root/ov/w /usr/bin && exec sleep 1800' && sleep 2 && systemctl is-active nt-overlay-test" >/dev/null
check "A15-overlay-critical" "$W1" 3 'crit and "mount-overlay:/usr/bin" in finds'

# --- 5. canary blocked --------------------------------------------------------------------
log "canary: /var/lib/nodetrust/canary made immutable on $W1"
on "$W1" "chattr +i /var/lib/nodetrust/canary && echo immutable" >/dev/null
check "canary-missing-critical" "$W1" 3 'crit and "ima-canary" in finds'
on "$W1" "chattr -i /var/lib/nodetrust/canary; systemctl stop nt-overlay-test; echo cleaned" >/dev/null

run_ssm_json "$REGION" "$VID" "journalctl -u nodetrust-verifier --no-pager -o cat | tail -100" >"$OUT/journal.txt" || true
echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT; both workers are critical now, destroy the cluster"
[ "$FAILS" -eq 0 ]
