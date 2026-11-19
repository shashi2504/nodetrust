#!/usr/bin/env bash
# Step 2.2: sign the reference manifest of a golden AMI.
#
#   1. download the manifest from the trust bucket (not a local copy) and
#      check that its entries match its digest
#   2. write the statement: AMI, snapshot, region, manifest hashes, key
#   3. sign the statement's SHA-256 with the KMS key (ECDSA_SHA_256)
#   4. verify the signature three ways: KMS Verify, openssl with the exported
#      public key, and the Go verifier code (pkg/manifest) that Phase 4 uses
#   5. check that a tampered statement and a wrong AMI are both rejected
#   6. upload statement.json and statement.sig to signed/<ami>/
#
# Usage: ./sign-manifest.sh <golden-ami-id>
# Env:   FORCE=1 replaces an existing signed statement for this AMI.
# The public key is pinned in infra/trust/manifest-signing-key.pem (created on
# first run; commit it). If KMS ever returns a different key the script stops.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3 openssl base64 go

AMI="${1:-}"
[ -n "$AMI" ] || die "usage: $0 <golden-ami-id>"
REGION="$(region)"
aws_ready

BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket 2>/dev/null)" ||
	die "no trust stack outputs; run 'terraform apply' in infra/trust first"
KEY="$(terraform -chdir=../trust output -raw signing_key_arn 2>/dev/null)" ||
	die "no signing key output; run 'terraform apply' in infra/trust (step 2.2 adds the key)"
PIN="$REPO/infra/trust/manifest-signing-key.pem"

role="$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI" \
	--query "Images[0].Tags[?Key=='role'].Value | [0]" --output text)"
[ "$role" = worker ] || die "$AMI is not tagged role=worker; pass the golden AMI"
SNAP="$(aws ec2 describe-images --region "$REGION" --image-ids "$AMI" \
	--query "Images[0].BlockDeviceMappings[?DeviceName=='/dev/sda1'].Ebs.SnapshotId | [0]" --output text)"

MKEY="manifests/$AMI/manifest.json.gz"
SPREFIX="signed/$AMI"
if aws s3api head-object --region "$REGION" --bucket "$BUCKET" --key "$SPREFIX/statement.json" >/dev/null 2>&1 && [ "${FORCE:-0}" != 1 ]; then
	die "s3://$BUCKET/$SPREFIX/statement.json already exists; FORCE=1 to replace it (the old version stays in bucket history)"
fi

W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2"
	FAILS=$((FAILS + 1))
}

# --- 1. manifest ------------------------------------------------------------------------
aws s3 cp --region "$REGION" --only-show-errors "s3://$BUCKET/$MKEY" "$W/manifest.json.gz"
python3 manifest.py digest --quiet "$W/manifest.json.gz" >/dev/null ||
	die "the manifest in s3://$BUCKET/$MKEY does not match its own entries_sha256"
pass manifest "s3://$BUCKET/$MKEY ($(stat -c %s "$W/manifest.json.gz") bytes, digest consistent)"

# --- 2. public key, pinned --------------------------------------------------------------
aws kms get-public-key --region "$REGION" --key-id "$KEY" --query PublicKey --output text |
	base64 -d >"$W/pub.der"
openssl pkey -pubin -inform DER -in "$W/pub.der" -out "$W/pub.pem"
spec="$(aws kms describe-key --region "$REGION" --key-id "$KEY" --query 'KeyMetadata.[KeySpec,KeyUsage,KeyState]' --output text)"
[ "$spec" = "$(printf 'ECC_NIST_P256\tSIGN_VERIFY\tEnabled')" ] || die "key $KEY is '$spec', want ECC_NIST_P256 SIGN_VERIFY Enabled"
if [ -f "$PIN" ]; then
	if cmp -s "$PIN" "$W/pub.pem"; then
		pass key-pinned "KMS public key matches infra/trust/manifest-signing-key.pem"
	else
		die "KMS returned a different public key than the pinned infra/trust/manifest-signing-key.pem; stop and find out why"
	fi
else
	cp "$W/pub.pem" "$PIN"
	pass key-pinned "first run: pinned the public key in infra/trust/manifest-signing-key.pem (commit it)"
fi
fpr="$(openssl pkey -pubin -in "$PIN" -outform DER | sha256sum | cut -d' ' -f1)"

# --- 3. statement and signature ---------------------------------------------------------
python3 manifest.py statement --manifest "$W/manifest.json.gz" --ami "$AMI" --snapshot "$SNAP" \
	--region "$REGION" --uri "s3://$BUCKET/$MKEY" --key-id "$KEY" -o "$W/statement.json" >/dev/null
openssl dgst -sha256 -binary "$W/statement.json" >"$W/digest.bin"
aws kms sign --region "$REGION" --key-id "$KEY" --message "fileb://$W/digest.bin" --message-type DIGEST \
	--signing-algorithm ECDSA_SHA_256 --query Signature --output text >"$W/statement.sig"
pass signed "statement sha256 $(sha256sum "$W/statement.json" | cut -c1-16)... with $KEY"

# --- 4. verify three ways ----------------------------------------------------------------
v="$(aws kms verify --region "$REGION" --key-id "$KEY" --message "fileb://$W/digest.bin" --message-type DIGEST \
	--signing-algorithm ECDSA_SHA_256 --signature "fileb://"<(base64 -d "$W/statement.sig") \
	--query SignatureValid --output text 2>&1)" || true
if [ "$v" = True ]; then pass verify-kms "KMS Verify accepts the signature"; else fail verify-kms "$v"; fi

if openssl dgst -sha256 -verify "$PIN" -signature <(base64 -d "$W/statement.sig") "$W/statement.json" >/dev/null; then
	pass verify-openssl "openssl accepts it with the pinned key (fingerprint ${fpr:0:16}...)"
else
	fail verify-openssl "openssl rejects the signature"
fi

(cd "$REPO" && go build -o "$W/verifier" ./cmd/verifier) || die "could not build cmd/verifier"
vm() { "$W/verifier" verify-manifest -public-key "$PIN" -signature "$W/statement.sig" -manifest "$W/manifest.json.gz" "$@"; }
if out="$(vm -statement "$W/statement.json" -ami "$AMI" 2>&1)"; then
	pass verify-go "$(head -1 <<<"$out")"
else
	fail verify-go "$out"
fi

# --- 5. negative checks ------------------------------------------------------------------
sed 's/"region":"/"region":"x/' "$W/statement.json" >"$W/tampered.json"
if out="$(vm -statement "$W/tampered.json" -ami "$AMI" 2>&1)"; then
	fail reject-tampered "Go verifier accepted a tampered statement"
else
	pass reject-tampered "$out"
fi
if out="$(vm -statement "$W/statement.json" -ami ami-00000000000000000 2>&1)"; then
	fail reject-wrong-ami "Go verifier accepted the statement for another AMI"
else
	pass reject-wrong-ami "$out"
fi

if [ "$FAILS" -ne 0 ]; then
	echo "SUMMARY fails=$FAILS (nothing uploaded)"
	exit 1
fi

# --- 6. upload ---------------------------------------------------------------------------
for f in statement.json statement.sig; do
	aws s3 cp --region "$REGION" --only-show-errors "$W/$f" "s3://$BUCKET/$SPREFIX/$f"
done
cp "$W/statement.json" "$HERE/statement-$AMI.json"
cp "$W/statement.sig" "$HERE/statement-$AMI.sig"
pass upload "s3://$BUCKET/$SPREFIX/{statement.json,statement.sig}"
echo "SUMMARY fails=0"
