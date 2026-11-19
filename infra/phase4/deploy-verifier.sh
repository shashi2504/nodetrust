#!/usr/bin/env bash
# Step 4.2: install the verifier service on the verifier host.
#
#   1. build the verifier; bundle it with its configuration, the verifier
#      client certificate and key (trust stack), the pinned manifest-signing
#      and Rekor keys, the runtime policy and the boot policy
#   2. ship the bundle through a presigned URL (deleted afterwards) and
#      install it over SSM: binary, /etc/nodetrust/verifier, systemd unit
#   3. start nodetrust-verifier.service and wait for two rounds; print the
#      status of every worker
#
# The allowed AMIs default to the ones in boot-policy.json; set
# ALLOWED_AMIS="ami-a ami-b" to choose. INTERVAL sets the challenge interval for healthy nodes (60s; shorter for others).
#
# Usage: ./deploy-verifier.sh   (with infra/cluster applied with manifest_bucket set)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform go python3 tar sha256sum

REGION="$(region)"
aws_ready
BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket)"
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
CPID="$(terraform -chdir=../cluster output -raw controlplane_id)"
CPIP="$(terraform -chdir=../cluster output -raw controlplane_ip)"
terraform -chdir=../cluster output -raw nodetrust_signing_pub_pem >/dev/null 2>&1 ||
	die "the cluster has no NodeTrust signing key yet; run terraform apply in infra/cluster (step 4.7)"
grep -q "^manifest_bucket *= *\"$BUCKET\"" ../cluster/terraform.tfvars 2>/dev/null ||
	die "infra/cluster/terraform.tfvars must set manifest_bucket = \"$BUCKET\" (the verifier role reads the manifests); add it and run terraform apply"
POLICY="$HERE/boot-policy.json"
[ -f "$POLICY" ] || die "no boot-policy.json; see step 4.1"
JOINREF="$HERE/join-reference.json"
[ -f "$JOINREF" ] || die "no join-reference.json; run ./join-reference.sh first (step 4.6)"
SIGNING_PIN="$REPO/infra/trust/manifest-signing-key.pem"
REKOR_PIN="$REPO/infra/trust/rekor-public-key.pem"
[ -f "$SIGNING_PIN" ] && [ -f "$REKOR_PIN" ] || die "pinned keys missing in infra/trust"
ALLOWED="${ALLOWED_AMIS:-$(python3 -c 'import json,sys; print(" ".join(sorted(json.load(open(sys.argv[1]))["amis"])))' "$POLICY")}"
[ -n "$ALLOWED" ] || die "no allowed AMIs"
OUT="$HERE/deploy-verifier-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
chmod 700 "$OUT"
log "verifier host $VID; allowed AMIs: $ALLOWED"
wait_ssm_online "$REGION" "$VID" 10 || die "verifier host $VID is not online in SSM"

# --- 0. NodeTrust resource in the cluster (step 4.7) ------------------------------------
log "NodeTrust resource, RBAC and admission policy on the control plane $CPID"
wait_ssm_online "$REGION" "$CPID" 10 || die "control plane $CPID is not online in SSM"
NTY="$(base64 -w0 "$HERE/k8s/nodetrust.yaml")"
run_ssm_json "$REGION" "$CPID" "set -e
K='kubectl --kubeconfig /etc/kubernetes/admin.conf'
echo '$NTY' | base64 -d | \$K apply -f -
\$K wait --for condition=established --timeout=60s crd/nodetrusts.trust.k8s-attest.io" >"$OUT/k8s.txt" ||
	die "applying k8s/nodetrust.yaml failed: $(cat "$OUT/k8s.txt")"
grep -v '^$' "$OUT/k8s.txt" | sed 's/^/    /'

# --- 1. bundle -----------------------------------------------------------------------
B="$OUT/bundle"
mkdir -p "$B"
VERSION="$(cd "$REPO" && git describe --always --dirty 2>/dev/null || echo dev)"
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
	-ldflags "-X nodetrust/internal/version.Version=$VERSION" -o "$B/nodetrust-verifier" ./cmd/verifier)
# shellcheck disable=SC2086 # one argument per allowed AMI
python3 - "$HERE/verifier/config.json.tmpl" "$B/config.json" "$BUCKET" "${INTERVAL:-60s}" "$CPIP" $ALLOWED <<'PY_EOF'
import json, sys
tmpl, out, bucket, interval, cpip, amis = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6:]
s = (open(tmpl).read().replace("@BUCKET@", bucket).replace("@INTERVAL@", interval)
     .replace("@AMIS@", json.dumps(amis)).replace("@CPIP@", cpip))
json.loads(s)
open(out, "w").write(s)
PY_EOF
cp "$HERE/verifier/nodetrust-verifier.service" "$POLICY" "$JOINREF" "$SIGNING_PIN" "$REKOR_PIN" "$REPO/infra/phase2/runtime-policy.json" "$B/"
terraform -chdir=../trust output -raw verifier_client_cert_pem >"$B/client.pem"
terraform -chdir=../trust output -raw verifier_client_key_pem >"$B/client.key"
terraform -chdir=../cluster output -raw cluster_ca_pem >"$B/kube-ca.pem"
terraform -chdir=../cluster output -raw verifier_kube_cert_pem >"$B/kube-client.pem"
terraform -chdir=../cluster output -raw verifier_kube_key_pem >"$B/kube-client.key"
terraform -chdir=../cluster output -raw nodetrust_signing_key_pem >"$B/trust-signing.key"
chmod 600 "$B/client.key" "$B/kube-client.key" "$B/trust-signing.key"
tar -czf "$OUT/bundle.tgz" -C "$B" .
rm -f "$B/client.key" "$B/kube-client.key" "$B/trust-signing.key" # private keys only travel inside the bundle
BSHA="$(sha256sum "$OUT/bundle.tgz" | cut -d' ' -f1)"
KEY="tools/verifier-service-$BSHA"
aws s3 cp --region "$REGION" --only-show-errors "$OUT/bundle.tgz" "s3://$BUCKET/$KEY"
trap 'aws s3 rm --region "$REGION" --only-show-errors "s3://$BUCKET/$KEY" || true; rm -f "$OUT/bundle.tgz"' EXIT
URL="$(aws s3 presign --region "$REGION" --expires-in 900 "s3://$BUCKET/$KEY")"

# --- 2. install ----------------------------------------------------------------------
S=/root/nt-verifier-install
E=/etc/nodetrust/verifier
run_ssm_json "$REGION" "$VID" "set -e
rm -rf $S; install -d -m 0700 $S
curl -fsS --max-time 120 -o $S/b.tgz '$URL'
echo '$BSHA  $S/b.tgz' | sha256sum -c --quiet -
tar -xzf $S/b.tgz -C $S
systemctl stop nodetrust-verifier 2>/dev/null || true
install -m 0755 $S/nodetrust-verifier /usr/local/bin/nodetrust-verifier
install -d -m 0755 $E
install -m 0600 $S/client.key $E/client.key
install -m 0600 $S/join-reference.json $E/join-reference.json
install -m 0600 $S/kube-client.key $E/kube-client.key
install -m 0600 $S/trust-signing.key $E/trust-signing.key
for f in config.json client.pem manifest-signing-key.pem rekor-public-key.pem runtime-policy.json boot-policy.json kube-ca.pem kube-client.pem; do install -m 0644 $S/\$f $E/\$f; done
install -m 0644 $S/nodetrust-verifier.service /etc/systemd/system/nodetrust-verifier.service
rm -rf $S
systemctl daemon-reload
systemctl enable --now nodetrust-verifier
sleep 3
systemctl is-active nodetrust-verifier
/usr/local/bin/nodetrust-verifier -version" >"$OUT/install.txt" ||
	die "install failed: $(cat "$OUT/install.txt")"
grep -q '^active' "$OUT/install.txt" || die "service not active: $(cat "$OUT/install.txt")"
log "installed: $(grep -v '^$' "$OUT/install.txt" | tail -1)"

# --- 3. first rounds -----------------------------------------------------------------
IV="${INTERVAL:-60s}"
sleep $((2 * ${IV%s} + 15))
run_ssm_json "$REGION" "$VID" "journalctl -u nodetrust-verifier --no-pager -o cat | tail -40; echo ----; cat /var/lib/nodetrust-verifier/status.json" >"$OUT/status.txt" ||
	die "could not read the status: $(cat "$OUT/status.txt")"
sed -n '1,/^----$/p' "$OUT/status.txt" | sed '$d'
python3 - "$OUT/status.txt" <<'PY_EOF'
import json, sys
t = open(sys.argv[1]).read().split("----\n", 1)[1]
s = json.loads(t.strip())
print(f"\nstatus at {s['updated_at']}:")
for n in s["nodes"]:
    print(f"  {n['instance_id']:20} {n['state']:14} {n.get('reason', '')[:150]}")
PY_EOF
log "saved $OUT"
