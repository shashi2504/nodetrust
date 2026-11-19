#!/usr/bin/env bash
# The Phase 4 gate (blueprint 11): clean nodes hold 100 for a long run, and
# injected changes give exactly the scores of Section 7.3. Run on fresh
# workers after deploy-verifier.sh.
#
#   1. soak: every 5 minutes for HOURS (default 4), every worker must be
#      verified, healthy, at 100, with no file against it, no finding and a
#      fresh signed NodeTrust update. Every sample is saved; a bad one is
#      reported with its time and files, and the soak goes on
#   2. A11 on worker 1: sshd config, sudoers, a cron file and a systemd unit,
#      one every 5 minutes, each read by root -> 95, 90, 85, 80; drift
#      isolated, unclassified, gradual, gradual; warning at the end
#
# The other scenarios with expected scores (A1, A7-A10, A13, A15) are in
# check-scoring.sh, check-probes.sh and check-join.sh.
#
# Keep the laptop awake for the whole run (SSM is polled from here).
# Usage: HOURS=4 ./phase4-gate.sh
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3 go

HOURS="${HOURS:-4}"
REGION="$(region)"
aws_ready
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
CPID="$(terraform -chdir=../cluster output -raw controlplane_id)"
ASG="$(terraform -chdir=../cluster output -raw workers_asg)"
OUT="$HERE/phase4-gate-$(date +%Y%m%d%H%M)"
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
terraform -chdir=../cluster output -raw nodetrust_signing_pub_pem >"$OUT/pub.pem"
(cd "$REPO" && go build -o "$OUT/nodetrust-verifier" ./cmd/verifier)

# shellcheck disable=SC2016
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -ge 2 ] || die "need two InService workers"
W1="${WORKERS[0]}"
log "workers: ${WORKERS[*]}; soak for $HOURS h, sampling every 5 minutes"
for w in "${WORKERS[@]}"; do
	check "healthy:$w" "$w" 5 'state == "verified" and tier == "healthy" and score == 100 and not crit and not unatt'
done
[ "$FAILS" -eq 0 ] || {
	echo "SUMMARY fails=$FAILS (stopped: the workers are not healthy to begin with)" | tee -a "$REPORT"
	exit 1
}

# --- 1. soak ----------------------------------------------------------------------------
end=$((SECONDS + HOURS * 3600))
samples=0
bad=0
while [ "$SECONDS" -lt "$end" ]; do
	samples=$((samples + 1))
	if run_ssm_json "$REGION" "$VID" "cat /var/lib/nodetrust-verifier/status.json" 2>>"$OUT/ssm-errors.txt" |
		sed -n '/^{/,$p' >"$OUT/status.json" && [ -s "$OUT/status.json" ]; then
		python3 - "$OUT/status.json" "$OUT/samples.jsonl" "${WORKERS[@]}" >"$OUT/sample.txt" <<'PY_EOF' || true
import datetime, json, sys
st, log, workers = sys.argv[1], sys.argv[2], sys.argv[3:]
nodes = {n["instance_id"]: n for n in json.load(open(st))["nodes"]}
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
bad = []
with open(log, "a") as f:
    for w in workers:
        n = nodes.get(w, {})
        row = {"at": now, "node": w, "state": n.get("state"), "tier": n.get("tier"), "score": n.get("score"),
               "critical": n.get("critical"), "unattested": n.get("unattested"),
               "files": [x["class"] + ":" + x["path"] for x in n.get("files") or []],
               "findings": [x["type"] + ":" + x.get("path", "") for x in n.get("findings") or []],
               "cycles": n.get("cycles"), "published": n.get("published_seq"), "publish_error": n.get("publish_error")}
        f.write(json.dumps(row) + "\n")
        ok = (row["state"] in ("verified", "outage") and row["tier"] == "healthy" and row["score"] == 100
              and not row["critical"] and not row["unattested"] and not row["files"] and not row["publish_error"])
        if not ok:
            bad.append(f"{w} {row['state']} {row['tier']} {row['score']} files={row['files']} findings={row['findings']} publish_error={row['publish_error']}")
if bad:
    print("\n".join(bad))
sys.exit(1 if bad else 0)
PY_EOF
	else
		echo "could not read status.json" >"$OUT/sample.txt"
	fi
	run_ssm_json "$REGION" "$CPID" "kubectl --kubeconfig /etc/kubernetes/admin.conf get nodetrusts -o json" 2>>"$OUT/ssm-errors.txt" |
		sed -n '/^{/,$p' >"$OUT/nodetrust.json" || true
	"$OUT/nodetrust-verifier" nodetrust-check -pub "$OUT/pub.pem" -max-age 3m <"$OUT/nodetrust.json" >"$OUT/nodetrust-check.txt" 2>&1 ||
		echo "NodeTrust: $(grep -v '^OK' "$OUT/nodetrust-check.txt" | tr '\n' ' ')" >>"$OUT/sample.txt"
	if grep -q '[^[:space:]]' "$OUT/sample.txt"; then
		bad=$((bad + 1))
		printf '%s sample %d:\n%s\n' "$(date -u +%H:%M:%S)" "$samples" "$(sed 's/^/    /' "$OUT/sample.txt")" | tee -a "$OUT/bad-samples.txt"
	else
		printf '%s sample %d: all workers healthy, 100, signed and fresh\n' "$(date -u +%H:%M:%S)" "$samples"
	fi
	sleep 300
done
if [ "$bad" -eq 0 ]; then
	pass "soak" "$samples samples over $HOURS h: every worker healthy at 100, nothing against it, NodeTrust signed and fresh"
else
	fail "soak" "$bad of $samples samples not clean (see bad-samples.txt)"
fi

# --- 2. A11: gradual drift ----------------------------------------------------------------
wait_ssm_online "$REGION" "$W1" 5 || die "$W1 not online in SSM"
step=0
for f in /etc/ssh/sshd_config /etc/sudoers /etc/cron.d/e2scrub_all /etc/systemd/system/nodetrust-ima-policy.service; do
	step=$((step + 1))
	log "A11 edit $step: $f on $W1"
	run_ssm_json "$REGION" "$W1" "echo '# nodetrust A11 test' >>$f && cat $f >/dev/null && echo edited" >>"$OUT/a11.txt" 2>&1 ||
		fail "A11-edit-$step" "could not edit $f: $(tail -2 "$OUT/a11.txt" | tr '\n' ' ')"
	want=$((100 - 5 * step))
	check "A11-step-$step" "$W1" 2 "score == $want"
	[ "$step" -lt 4 ] && sleep 240
done
check "A11-gradual" "$W1" 1 'tier == "warning" and score == 80 and "drift-gradual" in events and not crit'

echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT (samples.jsonl has every sample); worker $W1 is at warning"
[ "$FAILS" -eq 0 ]
