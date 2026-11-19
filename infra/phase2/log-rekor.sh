#!/usr/bin/env bash
# Step 2.3: record a signed manifest statement in the public Rekor log.
#
#   1. download signed/<ami>/statement.json and statement.sig from the trust
#      bucket and verify them with the pinned signing key first
#   2. submit a hashedrekord entry (statement SHA-256, signature, public key)
#      to Rekor v1; if it is already logged, fetch the existing entry
#   3. verify the returned entry offline with the Go verifier: it is for this
#      statement and key, the signed entry timestamp, the inclusion proof and
#      the signed checkpoint all check out against the pinned Rekor key
#   4. check that edited copies of the entry are rejected
#   5. upload the entry as signed/<ami>/rekor-entry.json
#
# Only the statement's hash, the signature and the public key become public;
# the statement and the manifest stay in the private bucket.
#
# Usage: ./log-rekor.sh <golden-ami-id>
# Env:   REKOR_URL (default https://rekor.sigstore.dev)
# The Rekor public key is pinned in infra/trust/rekor-public-key.pem on the
# first run (commit it). Later runs stop if the log presents a different key.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3 openssl curl go

AMI="${1:-}"
[ -n "$AMI" ] || die "usage: $0 <golden-ami-id>"
REGION="$(region)"
aws_ready
REKOR_URL="${REKOR_URL:-https://rekor.sigstore.dev}"

BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket 2>/dev/null)" ||
	die "no trust stack outputs; run 'terraform apply' in infra/trust first"
SIGNING_PIN="$REPO/infra/trust/manifest-signing-key.pem"
REKOR_PIN="$REPO/infra/trust/rekor-public-key.pem"
[ -f "$SIGNING_PIN" ] || die "no pinned signing key; run sign-manifest.sh first"
SPREFIX="signed/$AMI"

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2"
	FAILS=$((FAILS + 1))
}

# --- 1. signed statement ----------------------------------------------------------------
for f in statement.json statement.sig; do
	aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/$SPREFIX/$f" "$W/$f"
done
aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/manifests/$AMI/manifest.json.gz" "$W/manifest.json.gz"
(cd "$REPO" && go build -o "$W/verifier" ./cmd/verifier) || die "could not build cmd/verifier"
vm() {
	"$W/verifier" verify-manifest -public-key "$SIGNING_PIN" -statement "$W/statement.json" \
		-signature "$W/statement.sig" -manifest "$W/manifest.json.gz" -ami "$AMI" "$@"
}
out="$(vm 2>&1)" || die "the signed statement does not verify, so it will not be logged: $out"
pass statement "signed statement for $AMI verifies with the pinned key"

# --- 2. Rekor public key, pinned ------------------------------------------------------
curl -fsS --max-time 30 "$REKOR_URL/api/v1/log/publicKey" -o "$W/rekor.pem" ||
	die "could not fetch $REKOR_URL/api/v1/log/publicKey"
openssl pkey -pubin -in "$W/rekor.pem" -out "$W/rekor-norm.pem" 2>/dev/null ||
	die "Rekor public key is not a PEM public key"
if [ -f "$REKOR_PIN" ]; then
	cmp -s "$REKOR_PIN" "$W/rekor-norm.pem" ||
		die "Rekor presented a different public key than infra/trust/rekor-public-key.pem; stop and find out why"
	pass rekor-key-pinned "log key matches infra/trust/rekor-public-key.pem"
else
	cp "$W/rekor-norm.pem" "$REKOR_PIN"
	pass rekor-key-pinned "first run: pinned the log key in infra/trust/rekor-public-key.pem (commit it)"
fi
logid="$(openssl pkey -pubin -in "$REKOR_PIN" -outform DER | sha256sum | cut -d' ' -f1)"

# --- 3. submit, or fetch the existing entry --------------------------------------------
python3 - "$W" "$SIGNING_PIN" <<'EOF'
import base64, hashlib, json, sys
w, pin = sys.argv[1], sys.argv[2]
st = open(f"{w}/statement.json", "rb").read()
sig = open(f"{w}/statement.sig").read().strip()
pem = open(pin, "rb").read()
entry = {
    "apiVersion": "0.0.1",
    "kind": "hashedrekord",
    "spec": {
        "data": {"hash": {"algorithm": "sha256", "value": hashlib.sha256(st).hexdigest()}},
        "signature": {"content": sig, "publicKey": {"content": base64.b64encode(pem).decode()}},
    },
}
json.dump(entry, open(f"{w}/proposed.json", "w"))
EOF
code="$(curl -sS --max-time 60 -o "$W/resp.json" -D "$W/headers.txt" -w '%{http_code}' \
	-H 'Content-Type: application/json' --data-binary "@$W/proposed.json" "$REKOR_URL/api/v1/log/entries")" ||
	die "could not reach $REKOR_URL"
case "$code" in
201)
	pass rekor-submit "new entry created"
	;;
409)
	loc="$(awk 'tolower($1) == "location:" { print $2 }' "$W/headers.txt" | tr -d '\r')"
	[ -n "$loc" ] || die "Rekor says the entry exists (409) but gave no Location header"
	case "$loc" in http*) url="$loc" ;; *) url="$REKOR_URL$loc" ;; esac
	curl -fsS --max-time 60 "$url" -o "$W/resp.json" || die "could not fetch the existing entry $url"
	pass rekor-submit "already logged; fetched the existing entry"
	;;
*)
	die "Rekor returned HTTP $code: $(head -c 400 "$W/resp.json")"
	;;
esac

# --- 4. verify offline, then negative checks --------------------------------------------
if out="$(vm -rekor-entry "$W/resp.json" -rekor-key "$REKOR_PIN" 2>&1)"; then
	pass verify-rekor "$(grep '^OK rekor' <<<"$out")"
else
	fail verify-rekor "$out"
fi
idx="$(python3 -c 'import json,sys; e=next(iter(json.load(open(sys.argv[1])).values())); print(e["logIndex"])' "$W/resp.json")"
lid="$(python3 -c 'import json,sys; e=next(iter(json.load(open(sys.argv[1])).values())); print(e["logID"])' "$W/resp.json")"
if [ "$lid" = "$logid" ]; then
	pass rekor-log-id "entry logID matches the pinned key ($logid)"
else
	fail rekor-log-id "entry logID $lid, pinned key gives $logid"
fi

mutate() { # mutate <name> <python expression on e>
	python3 - "$W/resp.json" "$W/bad.json" "$2" <<'EOF'
import json, sys
src, dst, expr = sys.argv[1:4]
m = json.load(open(src))
uuid, e = next(iter(m.items()))
exec(expr)
json.dump({uuid: e}, open(dst, "w"))
EOF
	if out="$(vm -rekor-entry "$W/bad.json" -rekor-key "$REKOR_PIN" 2>&1)"; then
		fail "reject-$1" "Go verifier accepted an edited entry"
	else
		pass "reject-$1" "$(tail -1 <<<"$out")"
	fi
}
mutate time 'e["integratedTime"] += 1'
mutate proof 'p = e["verification"]["inclusionProof"]
if p["hashes"]:
    p["hashes"][0] = "00" * 32
else:
    p["rootHash"] = "00" * 32'
mutate checkpoint 'p = e["verification"]["inclusionProof"]; p["checkpoint"] = p["checkpoint"].replace("\n" + str(p["treeSize"]) + "\n", "\n" + str(p["treeSize"] + 1) + "\n", 1)'

if [ "$FAILS" -ne 0 ]; then
	echo "SUMMARY fails=$FAILS (entry not saved to the bucket)"
	cp "$W/resp.json" "$HERE/rekor-entry-$AMI.failed.json"
	exit 1
fi

# --- 5. save ------------------------------------------------------------------------------
aws s3 cp --region "$REGION" --only-show-errors "$W/resp.json" "s3://$BUCKET/$SPREFIX/rekor-entry.json"
cp "$W/resp.json" "$HERE/rekor-entry-$AMI.json"
pass upload "s3://$BUCKET/$SPREFIX/rekor-entry.json"
echo "INFO rekor-index              $idx (https://search.sigstore.dev/?logIndex=$idx)"
echo "SUMMARY fails=0"
