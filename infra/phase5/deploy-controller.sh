#!/usr/bin/env bash
# Phase 5: install the trust controller on the control plane host.
#
#   0. RBAC for User nodetrust-controller and the nodetrust-taints admission
#      policy (k8s/controller.yaml)
#   1. build the controller; bundle it with its configuration, its API client
#      certificate and key, the cluster CA and the pinned NodeTrust public key
#   2. ship the bundle through a presigned URL (deleted afterwards) and
#      install it over SSM as nodetrust-controller.service
#   3. wait for a few rounds and print the log and status
#
# DRY_RUN=1 (the default) logs every action and changes nothing; DRY_RUN=0
# runs the controller live.
#
# Usage: DRY_RUN=1 ./deploy-controller.sh   (after infra/phase4/deploy-verifier.sh)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
REPO="$(cd ../.. && pwd)"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform go python3 tar sha256sum

REGION="$(region)"
aws_ready
DRY="${DRY_RUN:-1}"
case "$DRY" in 0) DRYJSON=false ;; 1) DRYJSON=true ;; *) die "DRY_RUN must be 0 or 1" ;; esac
BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket)"
CPID="$(terraform -chdir=../cluster output -raw controlplane_id)"
CPIP="$(terraform -chdir=../cluster output -raw controlplane_ip)"
SG="$(terraform -chdir=../cluster output -raw quarantine_sg_id 2>/dev/null)" ||
	die "no quarantine group in the cluster yet; run terraform apply in infra/cluster (Phase 5)"
NACL="$(terraform -chdir=../cluster output -raw quarantine_nacl_id)"
OUT="$HERE/deploy-controller-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
chmod 700 "$OUT"
log "control plane $CPID; dry_run=$DRYJSON; quarantine $SG + $NACL"
wait_ssm_online "$REGION" "$CPID" 10 || die "control plane $CPID is not online in SSM"

# --- 0. RBAC and admission policy ------------------------------------------------------
Y="$(base64 -w0 "$HERE/k8s/controller.yaml")"
run_ssm_json "$REGION" "$CPID" "set -e
echo '$Y' | base64 -d | kubectl --kubeconfig /etc/kubernetes/admin.conf apply -f -" >"$OUT/k8s.txt" ||
	die "applying k8s/controller.yaml failed: $(cat "$OUT/k8s.txt")"
grep -v '^$' "$OUT/k8s.txt" | sed 's/^/    /'

# --- 1. bundle -----------------------------------------------------------------------
B="$OUT/bundle"
mkdir -p "$B"
VERSION="$(cd "$REPO" && git describe --always --dirty 2>/dev/null || echo dev)"
(cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
	-ldflags "-X nodetrust/internal/version.Version=$VERSION" -o "$B/nodetrust-controller" ./cmd/controller)
sed -e "s/@DRYRUN@/$DRYJSON/" -e "s/@CPIP@/$CPIP/" -e "s/@SG@/$SG/" -e "s/@NACL@/$NACL/" \
	"$HERE/controller/config.json.tmpl" >"$B/config.json"
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$B/config.json"
cp "$HERE/controller/nodetrust-controller.service" "$B/"
terraform -chdir=../cluster output -raw cluster_ca_pem >"$B/kube-ca.pem"
terraform -chdir=../cluster output -raw controller_kube_cert_pem >"$B/kube-client.pem"
terraform -chdir=../cluster output -raw controller_kube_key_pem >"$B/kube-client.key"
terraform -chdir=../cluster output -raw nodetrust_signing_pub_pem >"$B/trust-signing.pub"
chmod 600 "$B/kube-client.key"
tar -czf "$OUT/bundle.tgz" -C "$B" .
rm -f "$B/kube-client.key"
BSHA="$(sha256sum "$OUT/bundle.tgz" | cut -d' ' -f1)"
KEY="tools/controller-$BSHA"
aws s3 cp --region "$REGION" --only-show-errors "$OUT/bundle.tgz" "s3://$BUCKET/$KEY"
trap 'aws s3 rm --region "$REGION" --only-show-errors "s3://$BUCKET/$KEY" || true; rm -f "$OUT/bundle.tgz"' EXIT
URL="$(aws s3 presign --region "$REGION" --expires-in 900 "s3://$BUCKET/$KEY")"

# --- 2. install ----------------------------------------------------------------------
S=/root/nt-controller-install
E=/etc/nodetrust/controller
run_ssm_json "$REGION" "$CPID" "set -e
rm -rf $S; install -d -m 0700 $S
curl -fsS --max-time 120 -o $S/b.tgz '$URL'
echo '$BSHA  $S/b.tgz' | sha256sum -c --quiet -
tar -xzf $S/b.tgz -C $S
systemctl stop nodetrust-controller 2>/dev/null || true
install -m 0755 $S/nodetrust-controller /usr/local/bin/nodetrust-controller
install -d -m 0755 $E
install -m 0600 $S/kube-client.key $E/kube-client.key
for f in config.json kube-ca.pem kube-client.pem trust-signing.pub; do install -m 0644 $S/\$f $E/\$f; done
install -m 0644 $S/nodetrust-controller.service /etc/systemd/system/nodetrust-controller.service
rm -rf $S
systemctl daemon-reload
systemctl enable nodetrust-controller
systemctl restart nodetrust-controller
sleep 3
systemctl is-active nodetrust-controller" >"$OUT/install.txt" ||
	die "install failed: $(cat "$OUT/install.txt")"
grep -q '^active' "$OUT/install.txt" || die "service not active: $(cat "$OUT/install.txt")"

# --- 3. first rounds -----------------------------------------------------------------
sleep 20
run_ssm_json "$REGION" "$CPID" "journalctl -u nodetrust-controller --no-pager -o cat -n 40" >"$OUT/journal.txt" || true
sed 's/^/    /' "$OUT/journal.txt"
log "saved $OUT"
