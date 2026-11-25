#!/usr/bin/env bash
# Phase 6: Prometheus and Grafana on the verifier host.
#
#   1. bundle the Prometheus configuration (with the control plane's IP), the
#      alert rules, the unit, and Grafana's settings, data source and
#      dashboard; ship it through a presigned URL (deleted afterwards)
#   2. on the verifier host, over SSM: download Prometheus (pinned version,
#      checked against the release's sha256sums.txt), check the config and
#      rules with promtool, install Grafana from Grafana's signed apt
#      repository, set a random admin password, start both
#   3. check that both scrape targets are up, the five alert rules are
#      loaded and the dashboard is there
#
# Both listen on 127.0.0.1 only. To see the dashboard on the laptop:
#   aws ssm start-session --target <verifier_id> --document-name AWS-StartPortForwardingSession \
#     --parameters portNumber=3000,localPortNumber=3000
# then open http://localhost:3000 (needs the Session Manager plugin).
#
# Usage: ./deploy-monitoring.sh   (after deploy-verifier.sh and deploy-controller.sh)
#        PROM_VERSION=3.13.5 by default (the current LTS)
# shellcheck disable=SC2015 # "check && pass || fail": pass never fails
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3 tar sha256sum

REGION="$(region)"
aws_ready
PV="${PROM_VERSION:-3.13.5}"
BUCKET="$(terraform -chdir=../trust output -raw manifest_bucket)"
VID="$(terraform -chdir=../cluster output -raw verifier_id)"
CPIP="$(terraform -chdir=../cluster output -raw controlplane_ip)"
OUT="$HERE/deploy-monitoring-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
log "verifier host $VID; Prometheus $PV; controller metrics at $CPIP:9102"
wait_ssm_online "$REGION" "$VID" 10 || die "verifier host $VID is not online in SSM"

# --- 1. bundle -----------------------------------------------------------------------
B="$OUT/bundle"
mkdir -p "$B/grafana"
sed "s/@CPIP@/$CPIP/" prometheus/prometheus.yml.tmpl >"$B/prometheus.yml"
cp prometheus/rules.yml prometheus/nodetrust-prometheus.service "$B/"
cp -r grafana/. "$B/grafana/"
tar -czf "$OUT/bundle.tgz" -C "$B" .
BSHA="$(sha256sum "$OUT/bundle.tgz" | cut -d' ' -f1)"
KEY="tools/monitoring-$BSHA"
aws s3 cp --region "$REGION" --only-show-errors "$OUT/bundle.tgz" "s3://$BUCKET/$KEY"
trap 'aws s3 rm --region "$REGION" --only-show-errors "s3://$BUCKET/$KEY" || true' EXIT
URL="$(aws s3 presign --region "$REGION" --expires-in 900 "s3://$BUCKET/$KEY")"

# --- 2. install ----------------------------------------------------------------------
S=/root/nt-monitoring-install
P="prometheus-$PV.linux-amd64"
GH="https://github.com/prometheus/prometheus/releases/download/v$PV"
run_ssm_json "$REGION" "$VID" "set -e
rm -rf $S; install -d -m 0700 $S; cd $S
curl -fsS --max-time 120 -o b.tgz '$URL'
echo '$BSHA  b.tgz' | sha256sum -c --quiet -
mkdir bundle && tar -xzf b.tgz -C bundle
curl -fsSL --max-time 300 -o $P.tar.gz $GH/$P.tar.gz
curl -fsSL --max-time 60 -o sha256sums.txt $GH/sha256sums.txt
grep \" $P.tar.gz\$\" sha256sums.txt | sha256sum -c -
tar -xzf $P.tar.gz
install -m 0755 $P/prometheus $P/promtool /usr/local/bin/
install -d -m 0755 /etc/nodetrust/prometheus /etc/nodetrust/grafana
install -m 0644 bundle/prometheus.yml bundle/rules.yml /etc/nodetrust/prometheus/
promtool check config /etc/nodetrust/prometheus/prometheus.yml
install -m 0644 bundle/nodetrust-prometheus.service /etc/systemd/system/
cp -r bundle/grafana/dashboards /etc/nodetrust/grafana/
chmod -R a+rX /etc/nodetrust/grafana
if ! command -v grafana >/dev/null && ! [ -x /usr/sbin/grafana-server ]; then
  install -d -m 0755 /etc/apt/keyrings
  curl -fsSL --max-time 60 https://apt.grafana.com/gpg.key | gpg --dearmor -o /etc/apt/keyrings/grafana.gpg
  echo 'deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main' >/etc/apt/sources.list.d/grafana.list
  apt-get -o APT::Update::Error-Mode=any update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq grafana >/dev/null
fi
install -m 0640 -g grafana bundle/grafana/grafana.ini /etc/grafana/grafana.ini
install -m 0644 bundle/grafana/provisioning/datasources/nodetrust.yaml /etc/grafana/provisioning/datasources/nodetrust.yaml
install -m 0644 bundle/grafana/provisioning/dashboards/nodetrust.yaml /etc/grafana/provisioning/dashboards/nodetrust.yaml
if ! [ -s /etc/nodetrust/grafana-admin-password ]; then
  ( umask 077; openssl rand -hex 16 >/etc/nodetrust/grafana-admin-password )
  echo \"GF_SECURITY_ADMIN_PASSWORD=\$(cat /etc/nodetrust/grafana-admin-password)\" >>/etc/default/grafana-server
fi
systemctl daemon-reload
systemctl enable nodetrust-prometheus grafana-server >/dev/null 2>&1
systemctl restart nodetrust-prometheus grafana-server
rm -rf $S
prometheus --version | head -1
dpkg-query -W -f='grafana \${Version}\n' grafana" >"$OUT/install.txt" ||
	die "install failed: $(tail -20 "$OUT/install.txt")"
sed 's/^/    /' "$OUT/install.txt"

# --- 3. check ------------------------------------------------------------------------
FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2"
	FAILS=$((FAILS + 1))
}
sleep 40
run_ssm_json "$REGION" "$VID" "curl -fsS 127.0.0.1:9090/api/v1/targets?state=active; echo; echo ----
curl -fsS 127.0.0.1:9090/api/v1/rules?type=alert; echo; echo ----
curl -fsS '127.0.0.1:3000/api/search?query=nodetrust'; echo" >"$OUT/check.txt" || true
python3 - "$OUT/check.txt" >"$OUT/check-result.txt" <<'PY_EOF' || true
import json, sys
parts = open(sys.argv[1]).read().split("----\n")
def load(i):
    try:
        return json.loads(parts[i])
    except Exception:
        return None
t, r, g = load(0), load(1), load(2) if len(parts) > 2 else None
if t:
    for x in t["data"]["activeTargets"]:
        print("target", x["labels"]["job"], x["health"], x.get("lastError", ""))
else:
    print("target none")
if r:
    names = sorted(rule["name"] for grp in r["data"]["groups"] for rule in grp["rules"])
    print("rules", len(names), " ".join(names))
else:
    print("rules 0")
print("dashboard", " ".join(d["title"] for d in g) if g else "none")
PY_EOF
sed 's/^/    /' "$OUT/check-result.txt"
for j in verifier controller; do
	if grep -q "^target $j up" "$OUT/check-result.txt"; then pass "scrape-$j" "up"; else fail "scrape-$j" "$(grep "^target $j" "$OUT/check-result.txt")"; fi
done
grep -q "^rules 5 " "$OUT/check-result.txt" && pass "alert-rules" "5 rules loaded" || fail "alert-rules" "$(grep ^rules "$OUT/check-result.txt")"
grep -q "^dashboard .*nodetrust" "$OUT/check-result.txt" && pass "dashboard" "provisioned" || fail "dashboard" "$(grep ^dashboard "$OUT/check-result.txt")"
log "saved $OUT"
log "dashboard: aws ssm start-session --target $VID --document-name AWS-StartPortForwardingSession --parameters portNumber=3000,localPortNumber=3000"
[ "$FAILS" -eq 0 ]
