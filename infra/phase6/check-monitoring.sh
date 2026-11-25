#!/usr/bin/env bash
# The Phase 6 gate (blueprint 11): every metric in Section 9 has data and
# every alert fires in a test. Run on fresh workers with the verifier, the
# live controller (DRY_RUN=0) and the monitoring stack deployed.
#
#   1. both scrape targets up; the score, tier, component, mismatch, age,
#      duration and circuit-breaker metrics have data for healthy nodes
#   2. three unknown binaries on worker 2: score 70, degraded
#      -> NodeTrustDegraded fires
#   3. three config edits on worker 1, each seen before the next: 95, 90,
#      85, the third a gradual drift -> NodeTrustGradualDrift fires
#   4. a fake kubelet on worker 1: critical -> NodeTrustCritical fires; the
#      controller holds it (1 critical of 2 workers) -> TrustCircuitBreakerOpen
#      fires
#   5. approve: worker 1 is contained (containment phase and step times
#      have data); cut off, its last quote ages -> NodeAttestationStale
#      fires and failures are counted
#   6. all twelve Section 9 metrics have data, and all five alerts were
#      firing during the run (ALERTS in Prometheus)
#   7. worker 1 is terminated (its snapshot kept), so the group can launch a
#      replacement under the account's 8-vCPU limit
#
# Usage: ./check-monitoring.sh   (about 20 minutes)
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
OUT="$HERE/check-monitoring-$(date +%Y%m%d%H%M)"
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

# prom <promql>: "labels value" lines of an instant query, run on the
# verifier host (Prometheus listens on 127.0.0.1 there)
prom() {
	run_ssm_json "$REGION" "$VID" "curl -fsS --get 127.0.0.1:9090/api/v1/query --data-urlencode 'query=$1'" 2>/dev/null |
		python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for r in d.get("data", {}).get("result", []):
    m = {k: v for k, v in r["metric"].items() if k != "instance"}
    print(" ".join(f"{k}={v}" for k, v in sorted(m.items())), r["value"][1])'
}

# firing <alert>: the alert is firing now
firing() {
	local r
	r="$(prom "ALERTS{alertname=\"$1\",alertstate=\"firing\"}")"
	echo "${r:-not firing}"
	[ -n "$r" ]
}

# until_true <name> <minutes> <command...>
until_true() {
	local name="$1" deadline=$((SECONDS + $2 * 60))
	shift 2
	while :; do
		if "$@" >"$OUT/last.txt" 2>&1; then
			pass "$name" "$(tr '\n' ' ' <"$OUT/last.txt" | cut -c1-200)"
			return 0
		fi
		[ "$SECONDS" -lt "$deadline" ] || break
		sleep 15
	done
	fail "$name" "$(tr '\n' ' ' <"$OUT/last.txt" | cut -c1-200)"
	return 1
}

has_data() { # has_data <metric>: at least one series
	local r
	r="$(prom "count($1)")"
	echo "$1: ${r:-no data}"
	[ -n "$r" ]
}

# shellcheck disable=SC2016
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -ge 2 ] || die "need two InService workers"
W1="${WORKERS[0]}"
W2="${WORKERS[1]}"
log "worker 1 $W1, worker 2 $W2"
for w in "$W1" "$W2"; do
	check "healthy:$w" "$w" 5 'state == "verified" and tier == "healthy" and not crit and not unatt'
done
[ "$FAILS" -eq 0 ] || die "workers not healthy at the start; replace them first"
run_ssm_json "$REGION" "$CPID" "rm -f /var/lib/nodetrust-controller/approve/$W1 /var/lib/nodetrust-controller/approve/$W2" >/dev/null || true

# --- 1. healthy nodes -----------------------------------------------------------------------
target_up() { # target_up <job>
	local r
	r="$(prom "up{job=\"$1\"}")"
	echo "${r:-no target}"
	grep -q " 1$" <<<"$r"
}
until_true "scrape-verifier" 2 target_up verifier
until_true "scrape-controller" 2 target_up controller
for m in node_trust_score node_trust_tier node_trust_component_score node_trust_mismatched_files \
	node_attestation_age_seconds node_attestation_duration_seconds_bucket trust_circuit_breaker_open node_trust_drift_events_total; do
	until_true "data:$m" 2 has_data "$m"
done

# --- 2. degraded --------------------------------------------------------------------------
wait_ssm_online "$REGION" "$W2" 5 || die "$W2 not online in SSM"
run_ssm_json "$REGION" "$W2" "for i in 1 2 3; do cp /usr/bin/true /usr/local/bin/nt-mon-\$i && /usr/local/bin/nt-mon-\$i; done; echo ran" >/dev/null
check "verifier-degraded:$W2" "$W2" 3 'tier == "degraded" and score == 70'
until_true "alert-NodeTrustDegraded" 3 firing NodeTrustDegraded

# --- 3. gradual drift ---------------------------------------------------------------------
wait_ssm_online "$REGION" "$W1" 5 || die "$W1 not online in SSM"
want=100
for f in /etc/ssh/sshd_config /etc/sudoers /etc/cron.d/e2scrub_all; do
	run_ssm_json "$REGION" "$W1" "echo '# nodetrust Phase 6 test' >>$f && cat $f >/dev/null && echo edited" >/dev/null
	want=$((want - 5))
	check "edit:$f" "$W1" 3 "score == $want"
done
until_true "alert-NodeTrustGradualDrift" 3 firing NodeTrustGradualDrift

# --- 4. critical and the circuit breaker ----------------------------------------------------
run_ssm_json "$REGION" "$W1" "cp /usr/bin/true /usr/local/bin/kubelet && /usr/local/bin/kubelet && echo ran" >/dev/null
check "verifier-critical:$W1" "$W1" 3 'crit and "critical-binary" in finds'
until_true "alert-NodeTrustCritical" 3 firing NodeTrustCritical
until_true "alert-TrustCircuitBreakerOpen" 3 firing TrustCircuitBreakerOpen
in_phase() { # in_phase <phase>: worker 1's containment phase
	local r
	r="$(prom "node_containment_phase{node=\"$W1\",phase=\"$1\"} == 1")"
	echo "${r:-not $1}"
	[ -n "$r" ]
}
until_true "phase-held" 2 in_phase held

# --- 5. contained, then stale -------------------------------------------------------------
run_ssm_json "$REGION" "$CPID" "nodetrust-controller approve -instance $W1" >/dev/null
until_true "phase-released" 3 in_phase released
until_true "alert-NodeAttestationStale" 5 firing NodeAttestationStale
until_true "data:failures" 3 has_data 'node_attestation_failures_total{reason="unreachable"}'

# --- 6. every metric, every alert -----------------------------------------------------------
for m in node_trust_score node_trust_tier node_trust_component_score node_trust_mismatched_files \
	node_trust_critical_findings_total node_trust_drift_events_total node_attestation_age_seconds \
	node_attestation_failures_total node_attestation_duration_seconds_bucket node_containment_phase \
	node_containment_step_seconds_bucket trust_circuit_breaker_open; do
	if has_data "$m" >>"$OUT/metrics.txt"; then pass "section9:$m" "has data"; else fail "section9:$m" "no data"; fi
done
fired="$(prom 'max by (alertname) (max_over_time(ALERTS{alertstate="firing"}[3h]))' | sed 's/^alertname=//; s/ .*//' | sort | tr '\n' ' ')"
for a in NodeAttestationStale NodeTrustCritical NodeTrustDegraded NodeTrustGradualDrift TrustCircuitBreakerOpen; do
	if grep -qw "$a" <<<"$fired"; then pass "fired:$a" "during this run"; else fail "fired:$a" "fired: $fired"; fi
done
prom 'node_containment_step_seconds_sum / node_containment_step_seconds_count' | sed 's/^/    step seconds (mean): /' | tee -a "$REPORT"
prom 'histogram_quantile(0.95, sum by (le) (rate(node_attestation_duration_seconds_bucket[15m])))' |
	sed 's/^/    attestation p95 seconds: /' | tee -a "$REPORT"

# --- 7. make room for the replacement -------------------------------------------------------
run_ssm_json "$REGION" "$CPID" "nodetrust-controller terminate -instance $W1 -yes" 2>&1 | sed 's/^/    /' | tee -a "$REPORT" || true
echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT; worker $W2 is degraded: replace the workers before other checks"
[ "$FAILS" -eq 0 ]
