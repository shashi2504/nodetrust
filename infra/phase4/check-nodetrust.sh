#!/usr/bin/env bash
# Step 4.7 checks: signed NodeTrust objects in the cluster (blueprint 8.1).
# Run on fresh workers after deploy-verifier.sh.
#
#   1. one NodeTrust object per worker; every signature verifies with the
#      pinned public key (terraform output nodetrust_signing_pub_pem), each
#      object holds its own instance's state, and the update is fresh
#   2. updates keep coming: a minute later every sequence number is higher
#   3. a copy with the payload edited (score raised) fails the check
#   4. the cluster admin cannot write NodeTrust: changing the status,
#      deleting an object and creating a fake one are all denied by the
#      admission policy; RBAC gives the verifier's user NodeTrust and nothing
#      else
#   5. an unknown binary on worker 1 shows up in its signed state (warning,
#      90) within a minute
#
# Worker 1 ends at warning; replace the workers afterwards.
#
# Usage: ./check-nodetrust.sh   (takes about 5 minutes)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3 go

REGION="$(region)"
aws_ready
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
CPID="$(terraform -chdir=../cluster output -raw controlplane_id)"
ASG="$(terraform -chdir=../cluster output -raw workers_asg)"
OUT="$HERE/check-nodetrust-$(date +%Y%m%d%H%M)"
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
K='kubectl --kubeconfig /etc/kubernetes/admin.conf'
kube() { # kube <command>: run on the control plane as the cluster admin; output with errors, never fails
	run_ssm_json "$REGION" "$CPID" "$K $1" 2>&1 || true
}
fetch() { # fetch <file>: the NodeTrust list as JSON
	kube "get nodetrusts -o json" | sed -n '/^{/,$p' >"$1"
}
check_signed() { # check_signed <file>
	"$OUT/nodetrust-verifier" nodetrust-check -pub "$OUT/pub.pem" -max-age 3m <"$1"
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
wait_ssm_online "$REGION" "$CPID" 5 || die "control plane not online in SSM"
kube "get nodetrusts -o wide" | tee "$OUT/get.txt" | sed 's/^/    /'

# --- 1. signed and fresh ------------------------------------------------------------------
fetch "$OUT/list1.json"
if check_signed "$OUT/list1.json" >"$OUT/check1.txt" 2>&1; then
	n="$(grep -c '^OK ' "$OUT/check1.txt")"
	if grep -q "^OK $W1 " "$OUT/check1.txt" && grep -q "^OK $W2 " "$OUT/check1.txt"; then
		pass "signed" "$n objects verify with the pinned key"
	else
		fail "signed" "not every worker has an object: $(tr '\n' ' ' <"$OUT/check1.txt")"
	fi
else
	fail "signed" "$(tr '\n' ' ' <"$OUT/check1.txt")"
fi
sed 's/^/    /' "$OUT/check1.txt"

# --- 2. updates keep coming -----------------------------------------------------------------
sleep 75
fetch "$OUT/list2.json"
if python3 - "$OUT/list1.json" "$OUT/list2.json" "$W1" "$W2" >"$OUT/seq.txt" <<'PY_EOF'; then
import json, sys
def seqs(f):
    return {i["metadata"]["name"]: i["status"]["seq"] for i in json.load(open(f))["items"]}
a, b = seqs(sys.argv[1]), seqs(sys.argv[2])
ok = True
for w in sys.argv[3:5]:
    print(f"{w}: {a.get(w)} -> {b.get(w)}")
    ok &= a.get(w) is not None and b.get(w) is not None and b[w] > a[w]
sys.exit(0 if ok else 1)
PY_EOF
	pass "updates-continue" "$(tr '\n' ' ' <"$OUT/seq.txt")"
else
	fail "updates-continue" "$(tr '\n' ' ' <"$OUT/seq.txt")"
fi

# --- 3. a tampered copy -------------------------------------------------------------------
# Only worker 1's object is edited, and the edit must change the payload
# bytes: a newer seq and issue time (what replaying an old good state as new
# would need), and the tier and score flipped to something they are not.
# The age check is off here (-max-age 0), so only the signature can reject it.
if python3 - "$OUT/list2.json" "$OUT/tampered.json" "$W1" >"$OUT/tamper.txt" <<'PY_EOF'; then
import base64, json, sys
d = json.load(open(sys.argv[1]))
d["items"] = [i for i in d["items"] if i["metadata"]["name"] == sys.argv[3]]
s = d["items"][0]["status"]["signed"]
raw = base64.b64decode(s["payload"])
p = json.loads(raw)
p["seq"] += 1000
p["issued_at"] = "2099-01-01T00:00:00Z"
p["tier"], p["score"] = ("untrusted", 0) if p["tier"] == "healthy" else ("healthy", 100)
new = json.dumps(p, separators=(",", ":")).encode()
if new == raw:
    sys.exit("edit did not change the payload")
s["payload"] = base64.b64encode(new).decode()
json.dump(d, open(sys.argv[2], "w"))
print(f"seq {p['seq']}, tier {p['tier']} {p['score']}")
PY_EOF
	if "$OUT/nodetrust-verifier" nodetrust-check -pub "$OUT/pub.pem" -max-age 0 <"$OUT/tampered.json" >"$OUT/check-tampered.txt" 2>&1; then
		fail "tampered-copy" "accepted ($(cat "$OUT/tamper.txt")): $(tr '\n' ' ' <"$OUT/check-tampered.txt")"
	elif grep -q "^FAIL $W1 .*signature" "$OUT/check-tampered.txt"; then
		pass "tampered-copy" "$(cat "$OUT/tamper.txt"): $(grep '^FAIL' "$OUT/check-tampered.txt" | head -1)"
	else
		fail "tampered-copy" "rejected, but not for the signature: $(tr '\n' ' ' <"$OUT/check-tampered.txt")"
	fi
else
	fail "tampered-copy" "could not make the copy: $(cat "$OUT/tamper.txt")"
fi

# --- 4. nobody else writes NodeTrust ---------------------------------------------------------
denied() { # denied <name> <command>
	local out
	out="$(kube "$2")"
	printf '%s\n' "$out" >>"$OUT/admission.txt"
	if grep -q "only the nodetrust verifier" <<<"$out"; then
		pass "$1" "denied by the admission policy"
	else
		fail "$1" "$(tr '\n' ' ' <<<"$out" | cut -c1-200)"
	fi
}
denied "admin-patch-status" "patch nodetrust $W1 --subresource=status --type=merge -p '{\"status\":{\"tier\":\"healthy\",\"score\":100}}'"
denied "admin-delete" "delete nodetrust $W1"
denied "admin-create-fake" "create -f - <<'Y_EOF'
apiVersion: trust.k8s-attest.io/v1alpha1
kind: NodeTrust
metadata:
  name: i-00000000000000000
spec:
  instanceID: i-00000000000000000
Y_EOF"
# kubectl auth can-i exits 1 for "no" and warns about cluster-scoped
# resources; only the yes/no lines count.
can="$(kube "auth can-i patch nodetrusts/status --as nodetrust-verifier 2>/dev/null; $K auth can-i get secrets --as nodetrust-verifier 2>/dev/null; $K auth can-i patch nodes --as nodetrust-verifier 2>/dev/null; true" |
	grep -xE 'yes|no' | tr '\n' ' ' | xargs)"
if [ "$can" = "yes no no" ]; then
	pass "verifier-rbac" "nodetrusts/status: yes, secrets: no, nodes: no"
else
	fail "verifier-rbac" "$can"
fi

# --- 5. a change reaches the signed state ----------------------------------------------------
wait_ssm_online "$REGION" "$W1" 5 || die "$W1 not online in SSM"
run_ssm_json "$REGION" "$W1" "cp /usr/bin/true /usr/local/bin/nt-signed-test && /usr/local/bin/nt-signed-test && echo ran" >/dev/null
deadline=$((SECONDS + 120))
while :; do
	fetch "$OUT/list3.json"
	check_signed "$OUT/list3.json" >"$OUT/check3.txt" 2>&1 || true
	grep -q "^OK $W1 .*: warning 90 .*files=1" "$OUT/check3.txt" && break
	[ "$SECONDS" -lt "$deadline" ] || break
	sleep 15
done
if grep -q "^OK $W1 .*: warning 90 .*files=1" "$OUT/check3.txt"; then
	pass "change-signed" "$(grep "^OK $W1 " "$OUT/check3.txt")"
else
	fail "change-signed" "$(tr '\n' ' ' <"$OUT/check3.txt")"
fi

run_ssm_json "$REGION" "$VID" "journalctl -u nodetrust-verifier --no-pager -o cat | grep -i nodetrust | tail -20" >"$OUT/journal.txt" || true
echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT; worker $W1 is at warning, replace the workers before other checks"
[ "$FAILS" -eq 0 ]
