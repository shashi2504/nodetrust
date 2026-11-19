#!/usr/bin/env bash
# Step 3.2: enroll a NitroTPM instance and check a quote, over SSM.
#
#   1. build the agent (static linux/amd64) and the verifier here; ship the
#      agent to the node through a short-lived presigned S3 URL (sha256 checked)
#   2. agent enroll-request: EK and AK public areas from the node's TPM
#   3. verifier: compare the EK with ec2:GetInstanceTpmEkPub for this instance
#      and make a credential for the AK
#   4. agent activate: the TPM releases the secret only if the AK is loaded in
#      the TPM that holds that EK; verifier checks it and writes enrolled.json
#   5. agent quote with a fresh nonce (PCRs 0-10 plus the IMA log); verifier
#      checks the signature, nonce, PCR digest and the IMA replay to PCR 10
#   6. negative checks: the same quote with another nonce, and a secret from
#      one challenge against another challenge, must both fail; a second
#      enroll-request must show the same AK (keys are derived, not stored)
#
# Usage: ./enroll-node.sh <instance-id>   (a golden-AMI instance, e.g. a probe)
# Writes enroll-<instance>-<time>/ here.
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform go openssl python3 sha256sum base64

IID="${1:-}"
[ -n "$IID" ] || die "usage: $0 <instance-id>"
REGION="$(region)"
aws_ready
BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket)"
OUT="$HERE/enroll-$IID-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
chmod 700 "$OUT"
REPORT="$OUT/report.txt"

FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2" | tee -a "$REPORT"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2" | tee -a "$REPORT"
	FAILS=$((FAILS + 1))
}
info() { printf 'INFO %-26s %s\n' "$1" "$2" | tee -a "$REPORT"; }
ssm() { run_ssm_json "$REGION" "$IID" "$1"; }

log "waiting for SSM on $IID"
wait_ssm_online "$REGION" "$IID" 10 || die "$IID is not online in SSM"

# --- 1. build and ship -------------------------------------------------------------
log "building agent and verifier"
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o "$OUT/agent" ./cmd/agent)
(cd "$REPO" && go build -o "$OUT/verifier" ./cmd/verifier)
AGENT_SHA="$(sha256sum "$OUT/agent" | cut -d' ' -f1)"
KEY="tools/agent-$AGENT_SHA"
aws s3 cp --region "$REGION" --only-show-errors "$OUT/agent" "s3://$BUCKET/$KEY"
trap 'aws s3 rm --region "$REGION" --only-show-errors "s3://$BUCKET/$KEY" || true' EXIT
URL="$(aws s3 presign --region "$REGION" --expires-in 900 "s3://$BUCKET/$KEY")"
ssm "install -d -m 0700 /root/nt-agent && curl -fsS --max-time 120 -o /root/nt-agent/agent.new '$URL' && echo '$AGENT_SHA  /root/nt-agent/agent.new' | sha256sum -c --quiet - && install -m 0700 /root/nt-agent/agent.new /root/nt-agent/agent && rm /root/nt-agent/agent.new && /root/nt-agent/agent -version" >"$OUT/agent-version.txt" ||
	die "could not install the agent on $IID: $(cat "$OUT/agent-version.txt")"
pass agent-installed "$(tr -d '\n' <"$OUT/agent-version.txt") (sha256 ${AGENT_SHA:0:16}... checked on the node)"
A=/root/nt-agent/agent

# --- 2-4. enroll ---------------------------------------------------------------------
ssm "$A enroll-request" >"$OUT/enroll-request.json" || die "enroll-request failed: $(cat "$OUT/enroll-request.json")"
aws ec2 get-instance-tpm-ek-pub --region "$REGION" --instance-id "$IID" \
	--key-type rsa-2048 --key-format der --query KeyValue --output text >"$OUT/cloud-ek.b64"
pass cloud-ek "ec2:GetInstanceTpmEkPub returned the RSA-2048 EK for $IID"

V="$OUT/verifier"
if out="$("$V" enroll-challenge -instance "$IID" -cloud-ek "$OUT/cloud-ek.b64" -request "$OUT/enroll-request.json" \
	-challenge-out "$OUT/challenge.json" -pending-out "$OUT/pending.json" 2>&1)"; then
	while read -r l; do pass enroll-challenge "${l#OK }"; done <<<"$(grep '^OK' <<<"$out")"
	grep '^WARN' <<<"$out" | tee -a "$REPORT" || true
else
	die "verifier refused the enroll request: $out"
fi

CH_B64="$(base64 -w0 <"$OUT/challenge.json")"
ssm "$A activate -challenge $CH_B64" >"$OUT/response.json" || die "TPM refused the credential: $(cat "$OUT/response.json")"
if out="$("$V" enroll-finish -pending "$OUT/pending.json" -response "$OUT/response.json" -out "$OUT/enrolled.json" 2>&1)"; then
	pass enrolled "${out#OK }"
else
	fail enrolled "$out"
fi

# A second challenge: its secret must not finish the first one.
"$V" enroll-challenge -instance "$IID" -cloud-ek "$OUT/cloud-ek.b64" -request "$OUT/enroll-request.json" \
	-challenge-out "$OUT/challenge2.json" -pending-out "$OUT/pending2.json" >/dev/null
ssm "$A activate -challenge $(base64 -w0 <"$OUT/challenge2.json")" >"$OUT/response2.json"
if "$V" enroll-finish -pending "$OUT/pending.json" -response "$OUT/response2.json" -out /dev/null >/dev/null 2>&1; then
	fail reject-other-secret "the secret of challenge 2 finished challenge 1"
else
	pass reject-other-secret "a secret from another challenge does not complete this one"
fi

ssm "$A enroll-request" >"$OUT/enroll-request2.json"
ak1="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ak_public"])' "$OUT/enroll-request.json")"
ak2="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["ak_public"])' "$OUT/enroll-request2.json")"
if [ "$ak1" = "$ak2" ]; then
	pass ak-stable "a second load of the AK gives the same key (nothing stored on disk)"
else
	fail ak-stable "the AK changed between two loads"
fi

# --- 5. quote -------------------------------------------------------------------------
NONCE="$(openssl rand -hex 32)"
ssm "$A quote -nonce $NONCE -out /root/nt-agent/quote.json.gz && sha256sum /root/nt-agent/quote.json.gz && stat -c %s /root/nt-agent/quote.json.gz" >"$OUT/quote-remote.txt" ||
	die "quote failed: $(cat "$OUT/quote-remote.txt")"
want_sha="$(awk '/quote.json.gz$/ { print $1 }' "$OUT/quote-remote.txt")"
# The AWS CLI adds a newline after output that already ends in one, so take
# the last line that is a number, not simply the last line.
size="$(grep -E '^[0-9]+$' "$OUT/quote-remote.txt" | tail -1)"
[[ "$size" =~ ^[0-9]+$ ]] && [ -n "$want_sha" ] || die "could not read the quote's size and sha256 from the node: $(cat "$OUT/quote-remote.txt")"
: >"$OUT/quote.json.gz"
chunk=15000
for ((k = 0; k * chunk < size; k++)); do
	ssm "dd if=/root/nt-agent/quote.json.gz bs=$chunk skip=$k count=1 status=none | base64 -w0" |
		tr -d '[:space:]' | base64 -d >>"$OUT/quote.json.gz"
done
if [ "$(sha256sum "$OUT/quote.json.gz" | cut -d' ' -f1)" = "$want_sha" ]; then
	pass quote-fetched "$size bytes in $k chunks, sha256 matches the node"
else
	die "fetched quote does not match the node's sha256"
fi

if out="$("$V" check-quote -enrolled "$OUT/enrolled.json" -nonce "$NONCE" -quote "$OUT/quote.json.gz" 2>&1)"; then
	while read -r l; do pass check-quote "${l#OK }"; done <<<"$(grep '^OK' <<<"$out")"
	grep -E '^(INFO|PCR)' <<<"$out" | tee -a "$REPORT" >"$OUT/pcrs.txt"
else
	fail check-quote "$out"
fi

# --- 6. replay -----------------------------------------------------------------------
if "$V" check-quote -enrolled "$OUT/enrolled.json" -nonce "$(openssl rand -hex 32)" -quote "$OUT/quote.json.gz" >/dev/null 2>&1; then
	fail reject-replay "the quote was accepted with a different nonce"
else
	pass reject-replay "the same quote with a different nonce is rejected"
fi

rm -f "$OUT/pending.json" "$OUT/pending2.json" # they hold the secrets
echo "SUMMARY fails=$FAILS" | tee -a "$REPORT"
log "saved $OUT"
[ "$FAILS" -eq 0 ]
