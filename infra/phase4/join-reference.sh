#!/usr/bin/env bash
# Step 4.6: build join-reference.json, the expected content of the files a
# worker gets when it joins the cluster (blueprint 10.4). Run on a fresh
# cluster after check-cluster.sh, before deploy-verifier.sh.
#
# Two sources:
#   - the launch template's user data (from AWS, not from a node): the
#     discovery kubeconfig and the join configuration it writes, and the
#     cluster CA kubeadm copies out of the discovery kubeconfig
#   - two fresh workers (through SSM): the files kubeadm and kubelet write
#     (kubelet config, kubeconfig, kubeadm flags, instance config) and the
#     Calico CNI config. Node-specific values (instance ID, zone, address,
#     host name) are replaced by placeholders, and the two workers must give
#     the same templates; otherwise the script stops and shows the
#     difference
#
#   - the same two workers: the hashes of the binaries Calico installs on the
#     host (/opt/cni/bin, the FlexVolume driver), which must be equal on both
#
# Files that are the same on every node but cannot be captured (kubeadm
# deletes bootstrap-kubelet.conf after joining), and binaries that appear
# later, are left to fleet consensus in the verifier.
#
# Usage: ./join-reference.sh   (writes join-reference.json; review it)
set -euo pipefail
cd "$(dirname "$0")"
HERE="$PWD"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws terraform python3

REGION="$(region)"
aws_ready
ASG="$(terraform -chdir=../cluster output -raw workers_asg)"
OUT="$HERE/join-reference-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
chmod 700 "$OUT" # the user data holds the bootstrap token

# --- 1. the launch template's user data ---------------------------------------------------
read -r LT LTV < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].LaunchTemplate.[LaunchTemplateId,Version]' --output text)
aws ec2 describe-launch-template-versions --region "$REGION" --launch-template-id "$LT" --versions "$LTV" \
	--query 'LaunchTemplateVersions[0].LaunchTemplateData.UserData' --output text | base64 -d >"$OUT/userdata.sh"
log "user data of launch template $LT version $LTV ($(wc -c <"$OUT/userdata.sh") bytes)"

# --- 2. two workers ---------------------------------------------------------------------
# shellcheck disable=SC2016
mapfile -t WORKERS < <(aws autoscaling describe-auto-scaling-groups --region "$REGION" --auto-scaling-group-names "$ASG" \
	--query 'AutoScalingGroups[0].Instances[?LifecycleState==`InService`].InstanceId' --output text | tr '\t' '\n' | sed '/^$/d')
[ "${#WORKERS[@]}" -ge 2 ] || die "need two InService workers"
BINDIRS=(/opt/cni/bin /usr/libexec/kubernetes/kubelet-plugins/volume/exec)
CAPTURE=(/var/lib/kubelet/config.yaml /var/lib/kubelet/instance-config.yaml /var/lib/kubelet/kubeadm-flags.env
	/etc/kubernetes/kubelet.conf /etc/cni/net.d/10-calico.conflist
	/etc/kubernetes/nodetrust/discovery.conf /etc/kubernetes/nodetrust/join.yaml /etc/kubernetes/pki/ca.crt)
for w in "${WORKERS[@]:0:2}"; do
	wait_ssm_online "$REGION" "$w" 5 || die "$w not online in SSM"
	aws ec2 describe-instances --region "$REGION" --instance-ids "$w" \
		--query 'Reservations[0].Instances[0].[InstanceId,Placement.AvailabilityZone,PrivateIpAddress]' --output text >"$OUT/$w.facts"
	run_ssm_json "$REGION" "$w" "cd / && tar -czf - ${CAPTURE[*]#/} 2>/dev/null | base64 -w0" | tr -d '\n' >"$OUT/$w.tgz.b64"
	base64 -d "$OUT/$w.tgz.b64" >"$OUT/$w.tgz" || die "could not read the join files from $w"
	mkdir -p "$OUT/$w" && tar -xzf "$OUT/$w.tgz" -C "$OUT/$w"
	# The binaries Calico installs on the host (CNI plugins, FlexVolume driver).
	run_ssm_json "$REGION" "$w" "find ${BINDIRS[*]} -type f -exec sha256sum {} + 2>/dev/null | sort -k2" >"$OUT/$w.bin.sha256"
	log "captured $(find "$OUT/$w" -type f | wc -l) of ${#CAPTURE[@]} join files from $w"
done

# --- 3. build and check the reference ---------------------------------------------------------
python3 - "$OUT" "${WORKERS[0]}" "${WORKERS[1]}" "$HERE/join-reference.json" <<'PY_EOF'
import base64, datetime, hashlib, json, os, re, sys

out, w1, w2, dest = sys.argv[1:5]
ud = open(os.path.join(out, "userdata.sh")).read()
fails = 0

def heredoc(target):
    m = re.search(r"^cat >" + re.escape(target) + r" <<('?)NT_EOF\1\n(.*?)\nNT_EOF$", ud, re.S | re.M)
    if not m:
        sys.exit(f"error: no heredoc for {target} in the user data")
    return m.group(1) == "'", m.group(2) + "\n"

files = {}
quoted, disc = heredoc("/etc/kubernetes/nodetrust/discovery.conf")
assert quoted, "discovery.conf heredoc must be quoted"
files["/etc/kubernetes/nodetrust/discovery.conf"] = {"template": disc, "source": "launch template user data"}
quoted, join = heredoc("/etc/kubernetes/nodetrust/join.yaml")
assert not quoted
# Bash expands $AZ and $IID in this heredoc; nothing else may need expanding.
t = join.replace("$AZ", "${AZ}").replace("$IID", "${IID}")
if re.search(r"\$(?!\{(AZ|IID)\})|`|\\", t):
    sys.exit("error: join.yaml heredoc has expansions other than $AZ and $IID")
files["/etc/kubernetes/nodetrust/join.yaml"] = {"template": t, "source": "launch template user data ($AZ, $IID filled per node)"}
ca = re.search(r"certificate-authority-data: (\S+)", disc).group(1)
files["/etc/kubernetes/pki/ca.crt"] = {"template": base64.b64decode(ca).decode(),
                                       "source": "certificate-authority-data of the discovery kubeconfig"}

def facts(w):
    iid, az, ip = open(os.path.join(out, w + ".facts")).read().split()
    return iid, az, ip

def normalize(text, w):
    iid, az, ip = facts(w)
    host = "ip-" + ip.replace(".", "-")
    return text.replace(iid, "${IID}").replace(host, "${HOSTNAME}").replace(ip, "${IP}").replace(az, "${AZ}")

def render(t, w):
    iid, az, ip = facts(w)
    return (t.replace("${IID}", iid).replace("${AZ}", az).replace("${IP}", ip)
             .replace("${HOSTNAME}", "ip-" + ip.replace(".", "-")))

def node_file(w, p):
    f = os.path.join(out, w, p.lstrip("/"))
    return open(f).read() if os.path.exists(f) else None

for p in ["/var/lib/kubelet/config.yaml", "/var/lib/kubelet/instance-config.yaml", "/var/lib/kubelet/kubeadm-flags.env",
          "/etc/kubernetes/kubelet.conf", "/etc/cni/net.d/10-calico.conflist"]:
    a, b = node_file(w1, p), node_file(w2, p)
    if a is None or b is None:
        print(f"WARN {p}: missing on {w1 if a is None else w2}; left out (it will be unknown if measured)")
        continue
    ta, tb = normalize(a, w1), normalize(b, w2)
    if ta != tb:
        print(f"FAIL {p}: the two workers differ after replacing node values")
        import difflib
        print("".join(difflib.unified_diff(ta.splitlines(True), tb.splitlines(True), w1, w2)))
        fails += 1
        continue
    files[p] = {"template": ta, "source": f"captured from {w1} and {w2}, node values replaced"}

# Binaries: the same hash for the same path on both workers.
def binaries(w):
    out_ = {}
    for line in open(os.path.join(out, w + ".bin.sha256")):
        parts = line.rstrip("\n").split("  ", 1)
        if len(parts) == 2:
            out_[parts[1]] = parts[0]
    return out_
b1, b2 = binaries(w1), binaries(w2)
if not b1:
    print(f"FAIL no binaries found under the CNI and FlexVolume directories on {w1}")
    fails += 1
for p in sorted(set(b1) | set(b2)):
    if b1.get(p) != b2.get(p):
        print(f"FAIL {p}: {w1} {(b1.get(p) or 'missing')[:12]}, {w2} {(b2.get(p) or 'missing')[:12]}")
        fails += 1
    else:
        files[p] = {"sha256": [b1[p]], "source": f"hash on {w1} and {w2} after the join"}
print(f"INFO {len(b1)} installed binaries with the same hash on both workers")

# Every template, rendered for each worker, must equal the worker's file.
for w in (w1, w2):
    for p, f in sorted(files.items()):
        if "sha256" in f:
            continue  # checked above
        actual = node_file(w, p)
        want = hashlib.sha256(render(f["template"], w).encode()).hexdigest()
        got = hashlib.sha256(actual.encode()).hexdigest() if actual is not None else None
        if got != want:
            print(f"FAIL {w} {p}: rendered {want[:12]}, node has {got[:12] if got else 'nothing'}")
            fails += 1
        else:
            ph = sorted(set(re.findall(r"\$\{[A-Z]+\}", f["template"])))
            print(f"PASS {w} {p:<45} {want[:12]} {' '.join(ph) or '(same on every node)'}")

ref = {"format": "nodetrust-join-reference/1",
       "built": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
       "files": files,
       "consensus": ["/etc/kubernetes/bootstrap-kubelet.conf", "/opt/cni/bin/", "/host/opt/cni/bin/",
                     "/usr/libexec/kubernetes/kubelet-plugins/volume/exec/"]}
if fails:
    sys.exit(f"SUMMARY fails={fails}: join-reference.json not written")
tmp = dest + ".tmp"
with open(tmp, "w") as fh:
    json.dump(ref, fh, indent=2, sort_keys=True)
    fh.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, dest)
print(f"SUMMARY fails=0: wrote {dest} ({len(files)} files, {len(ref['consensus'])} consensus patterns); review it")
PY_EOF
log "saved $OUT"
