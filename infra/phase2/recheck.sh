#!/usr/bin/env bash
# Step 2.4: classify saved node snapshots again, without a cluster.
#
# Use after editing runtime-policy.json or after re-signing the manifest.
# Downloads the AMI's current manifest, statement, signature and Rekor entry
# into the folder, verifies the whole chain, and runs the Go verifier on
# A.tsv.gz (baseline) and on B.tsv.gz minus A (the tampering).
#
# Usage: ./recheck.sh node-<instance>-<time>
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform go python3

D="${1:-}"
[ -n "$D" ] && [ -f "$D/A.tsv.gz" ] && [ -f "$D/B.tsv.gz" ] || die "usage: $0 node-<instance>-<time> (a folder from check-node.sh)"
D="$(cd "$D" && pwd)"
REGION="$(region)"
aws_ready
BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket)"
AMI="$(python3 -c 'import gzip,sys
for l in gzip.open(sys.argv[1], "rt"):
    if l.startswith("# ami="): print(l.strip()[6:]); break' "$D/A.tsv.gz")"
[[ "$AMI" == ami-* ]] || die "no ami= line in $D/A.tsv.gz"

for f in statement.json statement.sig rekor-entry.json; do
	aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/signed/$AMI/$f" "$D/$f"
done
aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/manifests/$AMI/manifest.json.gz" "$D/manifest.json.gz"
python3 - runtime-policy.json harness-policy.json >"$D/runtime-policy.json" <<'PY_EOF'
import json, sys
p = json.load(open(sys.argv[1]))
p["runtime"] += json.load(open(sys.argv[2]))["runtime"]  # step 2.4 harness paths, never deployed
print(json.dumps(p, indent=1))
PY_EOF
(cd "$REPO" && go build -o "$D/verifier" ./cmd/verifier)

check() {
	"$D/verifier" check-ima -public-key "$REPO/infra/trust/manifest-signing-key.pem" \
		-statement "$D/statement.json" -signature "$D/statement.sig" -manifest "$D/manifest.json.gz" \
		-ami "$AMI" -rekor-entry "$D/rekor-entry.json" -rekor-key "$REPO/infra/trust/rekor-public-key.pem" \
		-policy "$D/runtime-policy.json" -show 200 "$@"
}
rc=0
echo "== baseline (A) =="
check -snapshot "$D/A.tsv.gz" | tee "$D/baseline.txt" || rc=1
echo
echo "== tampering (B minus A) =="
check -snapshot "$D/B.tsv.gz" -baseline "$D/A.tsv.gz" | tee "$D/tamper.txt" || true
exit "$rc"
