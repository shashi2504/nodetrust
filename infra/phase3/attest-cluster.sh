#!/usr/bin/env bash
# Step 3.3: attest every worker over the network, from the verifier host.
#
#   1. bundle the verifier binary, the verifier client certificate and key
#      (trust stack), and a rogue client certificate (self-signed, same name);
#      ship it to the verifier host through a presigned URL that is deleted
#      afterwards
#   2. for each worker: the laptop asks EC2 for its EK; the verifier host runs
#      attest-node against <worker IP>:9443 (enroll over mTLS, then two quotes
#      bound to the TLS session)
#   3. negative checks from the verifier host: no client certificate, and the
#      rogue certificate, must both be refused by the agent
#   4. compare PCRs 0-9 across workers (same AMI, so they should be identical)
#
# Usage: ./attest-cluster.sh   (with infra/cluster applied)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform go openssl python3 tar base64 sha256sum

REGION="$(region)"
aws_ready
BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket)"
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
ASG="$(terraform -chdir=../cluster output -raw workers_asg)"
OUT="$HERE/attest-cluster-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
chmod 700 "$OUT"
REPORT="$OUT/report.txt"

FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2" | tee -a "$REPORT"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2" | tee -a "$REPORT"
	FAILS=$((FAILS + 1))
}

# shellcheck disable=SC2016 # backticks are JMESPath literals, not shell
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -gt 0 ] || die "no InService workers in $ASG"
log "verifier host $VID, workers: ${WORKERS[*]}"
wait_ssm_online "$REGION" "$VID" 10 || die "verifier host $VID is not online in SSM"

# --- 1. bundle -----------------------------------------------------------------------
B="$OUT/bundle"
mkdir -p "$B"
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$B/verifier" ./cmd/verifier)
terraform -chdir=../trust output -raw verifier_client_cert_pem >"$B/client.pem"
terraform -chdir=../trust output -raw verifier_client_key_pem >"$B/client.key"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
	-subj "/CN=nodetrust-verifier" -addext extendedKeyUsage=clientAuth \
	-keyout "$B/rogue.key" -out "$B/rogue.pem" 2>/dev/null
chmod 600 "$B"/*.key
tar -czf "$OUT/bundle.tgz" -C "$B" .
rm -f "$B/client.key" # the key only travels inside the bundle
BSHA="$(sha256sum "$OUT/bundle.tgz" | cut -d' ' -f1)"
KEY="tools/verifier-bundle-$BSHA"
aws s3 cp --region "$REGION" --only-show-errors "$OUT/bundle.tgz" "s3://$BUCKET/$KEY"
trap 'aws s3 rm --region "$REGION" --only-show-errors "s3://$BUCKET/$KEY" || true; rm -f "$OUT/bundle.tgz"' EXIT
URL="$(aws s3 presign --region "$REGION" --expires-in 900 "s3://$BUCKET/$KEY")"
W=/root/nt-verifier
run_ssm_json "$REGION" "$VID" "rm -rf $W && install -d -m 0700 $W && curl -fsS --max-time 120 -o $W/b.tgz '$URL' && echo '$BSHA  $W/b.tgz' | sha256sum -c --quiet - && tar -xzf $W/b.tgz -C $W && rm $W/b.tgz && $W/verifier -version" >"$OUT/verifier-version.txt" ||
	die "could not install the verifier bundle on $VID: $(cat "$OUT/verifier-version.txt")"
pass verifier-installed "$(head -1 "$OUT/verifier-version.txt") on $VID (bundle sha256 checked)"

# --- 2-3. per worker -------------------------------------------------------------------
for IID in "${WORKERS[@]}"; do
	IP="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
		--query 'Reservations[0].Instances[0].PrivateIpAddress' --output text)"
	EK="$(aws ec2 get-instance-tpm-ek-pub --region "$REGION" --instance-id "$IID" \
		--key-type rsa-2048 --key-format der --query KeyValue --output text | tr -d '[:space:]')"
	D="$OUT/$IID"
	mkdir -p "$D"
	if run_ssm_json "$REGION" "$VID" "set -e; install -d -m 0700 $W/$IID; echo '$EK' >$W/$IID/cloud-ek.b64; $W/verifier attest-node -addr $IP:9443 -instance $IID -cloud-ek $W/$IID/cloud-ek.b64 -cert $W/client.pem -key $W/client.key -out $W/$IID -quotes 2; cat $W/$IID/pcrs.txt" >"$D/attest.txt" 2>&1; then
		grep '^OK' "$D/attest.txt" | while read -r l; do pass "attest:$IID" "${l#OK }"; done
		grep -E '^(INFO|PCR)' "$D/attest.txt" >"$D/pcrs.txt"
		grep '^WARN' "$D/attest.txt" | tee -a "$REPORT" || true
	else
		fail "attest:$IID" "$(tr '\n' ' ' <"$D/attest.txt" | cut -c1-400)"
	fi

	# The agent must refuse anyone without the verifier's client certificate.
	neg="$(run_ssm_json "$REGION" "$VID" "for c in none rogue; do if [ \$c = none ]; then a=''; else a='--cert $W/rogue.pem --key $W/rogue.key'; fi; if curl -sk --max-time 5 \$a -X POST -o /dev/null https://$IP:9443/v1/enroll; then echo \"\$c=answered\"; else echo \"\$c=refused\"; fi; done" || true)"
	if grep -q '^none=refused' <<<"$neg"; then pass "refuse-anonymous:$IID" "no client certificate: refused"; else fail "refuse-anonymous:$IID" "$neg"; fi
	if grep -q '^rogue=refused' <<<"$neg"; then pass "refuse-rogue:$IID" "self-signed certificate named nodetrust-verifier: refused"; else fail "refuse-rogue:$IID" "$neg"; fi
done

# --- 4. PCRs across workers -----------------------------------------------------------
python3 - "$OUT" "${WORKERS[@]}" <<'PY_EOF' | tee -a "$REPORT"
import sys, os
out, workers = sys.argv[1], sys.argv[2:]
pcrs = {}
for w in workers:
    p = os.path.join(out, w, "pcrs.txt")
    if not os.path.exists(p):
        continue
    for line in open(p):
        if line.startswith("PCR"):
            _, i, v = line.split()
            pcrs.setdefault(int(i), {})[w] = v
if len(workers) < 2 or not pcrs:
    print("INFO pcr-compare               fewer than two attested workers, nothing to compare")
    sys.exit(0)
for i in range(10):
    vals = set(pcrs.get(i, {}).values())
    state = "PASS" if len(vals) == 1 and len(pcrs.get(i, {})) == len(workers) else "INFO"
    v = next(iter(vals)) if len(vals) == 1 else "differs: " + ", ".join(f"{w}={pcrs[i].get(w, '-')[:16]}" for w in workers)
    print(f"{state} pcr{i}-same-on-all-workers {v[:64] if len(vals) == 1 else v}")
PY_EOF

echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT"
[ "$FAILS" -eq 0 ]
