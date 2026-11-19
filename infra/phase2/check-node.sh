#!/usr/bin/env bash
# Step 2.4: check a live worker's IMA log against the signed manifest.
#
#   1. download the node's AMI manifest, signed statement and Rekor entry,
#      and verify the whole chain (signature, AMI, manifest hashes, Rekor)
#   2. on the node (through SSM): snapshot the attested IMA measurements,
#      tamper on purpose (one new binary, one changed binary), snapshot again
#   3. bring both snapshots back and classify them with the Go verifier
#      against the manifest and runtime-policy.json
#   4. pass if both tampered files are caught: the new binary as unknown and
#      the changed one as mismatch. The baseline result is reported too; on a
#      first run it shows which runtime paths the policy still has to cover.
#
# Usage: ./check-node.sh <worker-instance-id>
# Writes everything to node-<instance>-<time>/ here, so the classification
# can be rerun offline with an edited policy (see README).
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3 go tar gzip base64 sha256sum

IID="${1:-}"
[ -n "$IID" ] || die "usage: $0 <worker-instance-id>"
REGION="$(region)"
aws_ready
BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket 2>/dev/null)" ||
	die "no trust stack outputs; run 'terraform apply' in infra/trust first"
SIGNING_PIN="$REPO/infra/trust/manifest-signing-key.pem"
REKOR_PIN="$REPO/infra/trust/rekor-public-key.pem"
[ -f "$SIGNING_PIN" ] && [ -f "$REKOR_PIN" ] || die "pinned keys missing in infra/trust; run sign-manifest.sh and log-rekor.sh first"

AMI="$(aws ec2 describe-instances --region "$REGION" --instance-ids "$IID" \
	--query 'Reservations[0].Instances[0].ImageId' --output text)"
[[ "$AMI" == ami-* ]] || die "could not read the AMI of $IID"
OUT="$HERE/node-$IID-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
REPORT="$OUT/report.txt"
log "node $IID runs $AMI; results go to $OUT"

FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2" | tee -a "$REPORT"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2" | tee -a "$REPORT"
	FAILS=$((FAILS + 1))
}

# --- 1. trusted manifest -------------------------------------------------------------
for f in statement.json statement.sig rekor-entry.json; do
	aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/signed/$AMI/$f" "$OUT/$f" ||
		die "no $f for $AMI in the bucket; build, sign and log its manifest first"
done
aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/manifests/$AMI/manifest.json.gz" "$OUT/manifest.json.gz"
python3 - runtime-policy.json harness-policy.json >"$OUT/runtime-policy.json" <<'PY_EOF'
import json, sys
p = json.load(open(sys.argv[1]))
p["runtime"] += json.load(open(sys.argv[2]))["runtime"]  # step 2.4 harness paths, never deployed
print(json.dumps(p, indent=1))
PY_EOF
(cd "$REPO" && go build -o "$OUT/verifier" ./cmd/verifier) || die "could not build cmd/verifier"
TRUST=(-public-key "$SIGNING_PIN" -statement "$OUT/statement.json" -signature "$OUT/statement.sig"
	-manifest "$OUT/manifest.json.gz" -ami "$AMI" -rekor-entry "$OUT/rekor-entry.json" -rekor-key "$REKOR_PIN")
if out="$("$OUT/verifier" verify-manifest "${TRUST[@]}" 2>&1)"; then
	pass trusted-manifest "signature, AMI binding, manifest hashes and Rekor entry all verify"
else
	die "the manifest for $AMI does not verify: $out"
fi

# --- 2. on the node ------------------------------------------------------------------
payload="$(tar -czf - -C "$HERE/node" ima_snapshot.py check-node-remote.sh -C "$REPO/infra/phase1" ima_replay.py | base64 -w0)"
log "snapshot, tamper, snapshot on $IID"
rc=0
run_ssm "$REGION" "$IID" "rm -rf /root/nt && mkdir -p /root/nt && cd /root/nt && echo $payload | base64 -d | tar xz && bash check-node-remote.sh $AMI $IID" >"$OUT/remote.txt" || rc=$?
tee -a "$REPORT" <"$OUT/remote.txt"
[ "$rc" -eq 0 ] || die "the node-side step failed; see $OUT/remote.txt"

# fetch <remote file> <local file>: in chunks, because SSM returns at most
# 24,000 characters of output per command.
fetch() {
	local src="$1" dst="$2" size chunk=15000 k=0 want got
	size="$(run_ssm "$REGION" "$IID" "stat -c %s $src" | tr -d '[:space:]')"
	[[ "$size" =~ ^[0-9]+$ ]] || die "could not stat $src on $IID"
	: >"$dst.b64"
	while [ $((k * chunk)) -lt "$size" ]; do
		run_ssm "$REGION" "$IID" "dd if=$src bs=$chunk skip=$k count=1 status=none | base64 -w0" |
			tr -d '[:space:]' | base64 -d >>"$dst"
		k=$((k + 1))
	done
	rm -f "$dst.b64"
	want="$(awk -v f="$(basename "$src" .tsv.gz)" '$2 == "snapshot-" f "-file" { print $6 }' "$OUT/remote.txt")"
	got="$(sha256sum "$dst" | cut -d' ' -f1)"
	if [ -n "$want" ] && [ "$got" = "$want" ]; then
		pass "fetch-$(basename "$dst")" "$size bytes in $k chunks, sha256 matches the node"
	else
		fail "fetch-$(basename "$dst")" "local sha256 $got, node ${want:-missing}"
	fi
}
rm -f "$OUT/A.tsv.gz" "$OUT/B.tsv.gz"
fetch /root/nt-ima/A.tsv.gz "$OUT/A.tsv.gz"
fetch /root/nt-ima/B.tsv.gz "$OUT/B.tsv.gz"

# --- 3. classify ---------------------------------------------------------------------
check() { "$OUT/verifier" check-ima "${TRUST[@]}" -policy "$OUT/runtime-policy.json" "$@"; }
base_rc=0
check -snapshot "$OUT/A.tsv.gz" -show 200 >"$OUT/baseline.txt" 2>&1 || base_rc=$?
check -snapshot "$OUT/B.tsv.gz" -baseline "$OUT/A.tsv.gz" -show 200 >"$OUT/tamper.txt" 2>&1 || true

# --- 4. verdict ----------------------------------------------------------------------
in_section() { # in_section <file> <SECTION> <path>: is the path listed under that heading?
	awk -v s="$2:" -v p="$3" '
		/^[A-Z]+:$/ { cur = $0; next }
		/^$/ { cur = "" }
		cur == s && $NF == p { found = 1 }
		END { exit !found }' "$1"
}
if in_section "$OUT/tamper.txt" UNKNOWN /usr/local/bin/nt-evil; then
	pass detect-new-binary "/usr/local/bin/nt-evil reported as unknown"
else
	fail detect-new-binary "/usr/local/bin/nt-evil not reported as unknown (see tamper.txt)"
fi
if in_section "$OUT/tamper.txt" MISMATCH /usr/bin/whoami; then
	pass detect-changed-binary "/usr/bin/whoami reported as mismatch"
else
	fail detect-changed-binary "/usr/bin/whoami not reported as mismatch (see tamper.txt)"
fi
if in_section "$OUT/baseline.txt" MISMATCH /usr/bin/whoami || in_section "$OUT/baseline.txt" UNKNOWN /usr/local/bin/nt-evil; then
	fail baseline-before-tamper "snapshot A already contains the tampered files"
else
	pass baseline-before-tamper "snapshot A has neither tampered file"
fi

{
	echo
	echo "== baseline (snapshot A, all attested measurements) =="
	awk '/^all attested/ { on = 1 } on && /^$/ { exit } on' "$OUT/baseline.txt"
	grep '^RESULT' "$OUT/baseline.txt" || cat "$OUT/baseline.txt"
	echo
	echo "== after tampering (snapshot B, new measurements only) =="
	sed -n '/^measurements new since/,$p' "$OUT/tamper.txt"
} | tee -a "$REPORT"

if [ "$base_rc" -eq 0 ]; then
	pass baseline-clean "every baseline measurement is in the manifest or covered by the policy"
else
	printf 'INFO %-26s %s\n' baseline-clean "not yet: see the MISMATCH and UNKNOWN lists in $OUT/baseline.txt" | tee -a "$REPORT"
fi
echo "SUMMARY fails=$FAILS (tamper detection; baseline listed separately)" | tee -a "$REPORT"
log "saved $OUT"
[ "$FAILS" -eq 0 ]
