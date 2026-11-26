#!/usr/bin/env python3
"""Phase 7 evaluation runner (blueprint Section 12).

Runs attack scenarios on the live NitroTPM cluster, one at a time on worker 1
(worker 2 stays clean as the healthy peer), and records one row per run in
runs.csv plus the raw evidence of each run in raw/<scenario>-<n>/:

    ./evaluate.py run A9 A8 --runs 2      # run scenarios
    ./evaluate.py list                    # what each scenario does and expects
    ./evaluate.py report                  # results.md from runs.csv

Each run:
  1. waits until both workers are verified, healthy, at 100
  2. injects the scenario on worker 1 over SSM; the command prints the
     worker's clock when the changed file was used (t0)
  3. waits for the verifier's finding and reads its time from the node's
     track (verifier clock); detection time = finding - t0
  4. for a critical finding: waits for the controller's containment
     (approving it at the circuit breaker if it holds) and reads each step's
     time from the controller's state; then terminates the quarantined
     instance through the controller (the account's 8-vCPU limit leaves no
     room for a replacement while it runs)
  5. otherwise replaces worker 1 through the Auto Scaling group, so the next
     run starts on a fresh node
  6. the baseline verdict (blueprint 12.4: any mismatch makes the node
     untrusted) is worked out from the same findings

Standard library only; uses the AWS CLI and Terraform outputs like the
other scripts. All times are UTC.
"""

import argparse
import csv
import datetime as dt
import json
import shlex
import traceback
import os
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLUSTER = os.path.join(HERE, "..", "cluster")
RUNS_CSV = os.path.join(HERE, "runs.csv")
RAW = os.path.join(HERE, "raw")
K = "kubectl --kubeconfig /etc/kubernetes/admin.conf"

# Every scenario: what is done on worker 1 and what should follow.
#   kind     critical | score | prevented
#   expect   critical: the finding type; score: (score, tier, drift class)
#   cmd      shell run as root on worker 1; it must end by printing
#            T=<epoch seconds> right after the changed file is used
#   timeout  minutes to wait for the finding
NOW = "echo T=$(date +%s.%N)"


def swap(path):
    """Shell that replaces a (possibly running) binary with a changed copy:
    writing to a running executable fails with ETXTBSY, so the copy gets one
    byte appended and is renamed over the original."""
    return f"cp -a {path} {path}.nt && printf '\\0' >>{path}.nt && mv {path}.nt {path}"
SCENARIOS = {
    "A1": dict(kind="critical", expect="critical-binary", timeout=5,
               what="replace kubelet (one byte appended) and restart it",
               cmd=f"{swap('/usr/bin/kubelet')} && systemctl restart kubelet && {NOW}"),
    "A2": dict(kind="critical", expect="critical-binary", timeout=5,
               what="replace containerd (one byte appended) and restart it",
               cmd=f"{swap('/usr/bin/containerd')} && systemctl restart containerd && {NOW}"),
    "A4": dict(kind="critical", expect="evidence-missing", timeout=8,
               what="stop the attestation agent",
               cmd=f"systemctl stop nodetrust-agent && {NOW}"),
    "A7": dict(kind="critical", expect="boot-file", timeout=15,
               what="stage a changed kernel in /boot (not rebooted; found by the next sweep, which reads /boot)",
               cmd=f"k=$(readlink -f /boot/vmlinuz) && cp $k /boot/vmlinuz-nt-staged && printf '\\0' >>/boot/vmlinuz-nt-staged && {NOW}"),
    "A8": dict(kind="score", expect=(90, "warning", "isolated"), timeout=5,
               what="change one system binary (/usr/bin/yes) and run it",
               cmd=f"printf '\\0' >>/usr/bin/yes && /usr/bin/yes | head -1 >/dev/null && {NOW}"),
    "A9": dict(kind="score", expect=(90, "warning", "isolated"), timeout=5,
               what="copy an unknown binary into /usr/local/bin and run it",
               cmd=f"cp /usr/bin/true /usr/local/bin/nt-a9 && /usr/local/bin/nt-a9 && {NOW}"),
    "A10": dict(kind="score", expect=(72.5, "degraded", "sudden"), timeout=5,
                what="edit kubelet and containerd config, restart both in one cycle",
                cmd="echo '# nodetrust A10' >>/var/lib/kubelet/config.yaml && echo '# nodetrust A10' >>/etc/containerd/config.toml"
                    f" && systemctl restart containerd kubelet && {NOW}"),
    "A11": dict(kind="score", expect=(80, "warning", "gradual"), timeout=5,
                what="edit sshd config, sudoers, a cron file and a systemd unit, one every 5 minutes, each read",
                steps=["/etc/ssh/sshd_config", "/etc/sudoers", "/etc/cron.d/e2scrub_all",
                       "/etc/systemd/system/nodetrust-ima-policy.service"], every=300),
    "A12": dict(kind="critical", expect="critical-binary", timeout=5, pods=True,
                what="replace kubelet and freeze it (it can no longer evict pods); pods must still move",
                cmd=f"{swap('/usr/bin/kubelet')} && systemctl restart kubelet && {NOW} && sleep 2"
                    " && kill -STOP $(pidof kubelet) && echo frozen"),
    "A13": dict(kind="critical", expect="critical-binary", timeout=15,
                what="change runc but never run it (found by the next sweep)",
                cmd=f"r=$(command -v runc || echo /usr/sbin/runc) && printf '\\0' >>$r && {NOW}"),
    "A14": dict(kind="prevented", timeout=3,
                what="run a binary from a memfd",
                cmd="python3 -c \"import os\ntry:\n  fd=os.memfd_create('x')\n  os.write(fd,open('/usr/bin/true','rb').read())\n"
                    "  os.execv('/proc/self/fd/%d'%fd,['x'])\nexcept OSError as e:\n  print('REFUSED',e.strerror)\"; "
                    + NOW),
    "A15": dict(kind="critical", expect="mount-overlay", timeout=5,
                what="build an overlay over /usr/bin in a private mount namespace and run a binary from it",
                # the time is taken before systemd-run: the mount happens in the background
                cmd=f"mkdir -p /root/ov/u /root/ov/w && {NOW} && systemd-run --unit nt-a15 unshare -m --propagation private sh -c"
                    " 'mount -t overlay overlay -o lowerdir=/usr/bin,upperdir=/root/ov/u,workdir=/root/ov/w /usr/bin"
                    " && /usr/bin/true && exec sleep 1800' && sleep 2"),
    "A16": dict(kind="critical", expect="ima-canary", timeout=5,
                what="block the canary (stands in for a frozen IMA: the canary entry never appears)",
                cmd=f"chattr +i /var/lib/nodetrust/canary && {NOW}"),
    "A17": dict(kind="prevented", timeout=3,
                what="run a binary from /dev/shm, directly and through ld.so",
                cmd="cp /usr/bin/true /dev/shm/nt-a17; /dev/shm/nt-a17 2>/dev/null && echo RAN-DIRECT || echo REFUSED direct;"
                    " /lib64/ld-linux-x86-64.so.2 /dev/shm/nt-a17 2>/dev/null && echo RAN-LDSO || echo REFUSED ldso; " + NOW),
}
NOT_LIVE = {
    "A3": "Falco is not installed in the golden AMI; the critical-file rule for it is unit-tested (pkg/trust).",
    "A5": "needs an agent that replays an old response; the TLS-bound nonce check is in the simulator tests (pkg/verifier client_sim_test.go).",
    "A6": "needs an agent that sends an edited IMA log; replay mismatch is in pkg/ima tests and `make demo` part 2.",
}

FIELDS = ["scenario", "run", "worker", "started", "t_used", "kind", "expected", "result", "match",
          "finding", "score", "tier", "drift", "detect_s", "contained", "held", "cordon_s", "isolate_s",
          "snapshot_s", "replace_s", "release_s", "pods_moved_s", "baseline_untrusted", "nodes_lost",
          "nodes_lost_baseline", "notes"]


# --- small helpers -------------------------------------------------------------------------

def log(msg):
    print(f"==> {dt.datetime.now(dt.timezone.utc):%H:%M:%S} {msg}", flush=True)


def sh(args, check=True):
    p = subprocess.run(args, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"{' '.join(args[:4])}...: {p.stderr.strip()[-400:]}")
    return p.stdout


def tf(name):
    return sh(["terraform", f"-chdir={CLUSTER}", "output", "-raw", name]).strip()


REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or \
    sh(["aws", "configure", "get", "region"], check=False).strip()


def aws(*args):
    return sh(["aws", "--region", REGION, *args])


def ssm(instance, command, timeout=900):
    """Runs a shell command as root on an instance; returns (ok, stdout)."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"commands": [command], "executionTimeout": [str(timeout)]}, f)
        pfile = f.name
    try:
        cid = aws("ssm", "send-command", "--instance-ids", instance, "--document-name", "AWS-RunShellScript",
                  "--parameters", f"file://{pfile}", "--query", "Command.CommandId", "--output", "text").strip()
    finally:
        os.unlink(pfile)
    deadline = time.time() + timeout + 60
    while time.time() < deadline:
        time.sleep(2)
        r = subprocess.run(["aws", "--region", REGION, "ssm", "get-command-invocation", "--command-id", cid,
                            "--instance-id", instance, "--output", "json"], capture_output=True, text=True)
        if r.returncode != 0:
            continue
        inv = json.loads(r.stdout)
        if inv["Status"] in ("Pending", "InProgress", "Delayed"):
            continue
        return inv["Status"] == "Success", inv["StandardOutputContent"] + inv["StandardErrorContent"]
    return False, "SSM command timed out"


def until(fn, minutes, every=5):
    """Calls fn until it returns something true, or the time is up (None)."""
    deadline = time.time() + minutes * 60
    while True:
        try:
            v = fn()
        except Exception as e:  # a failed read (SSM hiccup) is retried
            v, last = None, e
        if v:
            return v
        if time.time() > deadline:
            return None
        time.sleep(every)


def ts(s):
    """RFC 3339 (Go, nanoseconds) to epoch seconds."""
    s = s.replace("Z", "+00:00")
    if "." in s:
        head, rest = s.split(".", 1)
        frac, tz = rest[:-6], rest[-6:]
        s = f"{head}.{frac[:6]}{tz}"
    return dt.datetime.fromisoformat(s).timestamp()


def iso(t):
    return dt.datetime.fromtimestamp(t, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# --- cluster state -------------------------------------------------------------------------

class Cluster:
    def __init__(self):
        self.vid = tf("verifier_id")
        self.cpid = tf("controlplane_id")
        self.asg = tf("workers_asg")

    def workers(self):
        out = aws("autoscaling", "describe-auto-scaling-groups", "--auto-scaling-group-names", self.asg,
                  "--query", "AutoScalingGroups[0].Instances[?LifecycleState=='InService'].InstanceId", "--output", "json")
        return sorted(json.loads(out))

    def json_from(self, instance, cmd):
        ok, out = ssm(instance, cmd, timeout=120)
        if not ok:
            raise RuntimeError(out[-300:])
        return json.loads(out[out.index("{"):])

    # SSM returns at most 24,000 characters of output, and state.json and
    # status.json keep an entry for every node ever seen, so they outgrow that
    # after a few runs. The host picks out only the entries asked for and
    # prints them compact.
    def pick(self, instance, path, expr):
        py = (f"import json; d=json.load(open('{path}')); "
              f"print(json.dumps({expr}, separators=(',', ':')))")
        return self.json_from(instance, f"python3 -c {shlex.quote(py)}")

    def verifier(self, ids=None):
        ids = ids or self.workers()
        nodes = self.pick(self.vid, "/var/lib/nodetrust-verifier/status.json",
                          f"{{'nodes': [n for n in d['nodes'] if n['instance_id'] in {ids!r}]}}")["nodes"]
        return {n["instance_id"]: n for n in nodes}

    def track(self, node):
        # the last 200 history events are plenty for one run
        return self.pick(self.vid, f"/var/lib/nodetrust-verifier/track/{node}.json",
                         "dict(d, history=(d.get('history') or [])[-200:])")

    def controller(self, node):
        """The controller's record for one instance, or None."""
        return self.pick(self.cpid, "/var/lib/nodetrust-controller/state.json",
                         f"{{'r': d.get({node!r})}}")["r"]

    def healthy(self, node):
        n = self.verifier([node]).get(node)
        return n and n.get("state") == "verified" and n.get("tier") == "healthy" and n.get("score") == 100 \
            and not n.get("critical") and not n.get("unattested")

    def kube(self, cmd):
        ok, out = ssm(self.cpid, f"{K} {cmd}", timeout=120)
        return out

    def node_name(self, instance):
        out = self.kube("get nodes -o jsonpath='{range .items[*]}{.spec.providerID} {.metadata.name}{\"\\n\"}{end}'")
        for line in out.splitlines():
            if line.split(" ")[0].endswith("/" + instance):
                return line.split(" ")[1]
        return None


# --- one run --------------------------------------------------------------------------------

def prepare(c, again=False):
    """Two healthy workers; returns (w1, w2). Replaces a worker that is not healthy."""
    def two():
        ws = c.workers()
        return ws if len(ws) >= 2 else None
    ws = until(two, 20, 20)
    if not ws:
        raise RuntimeError("fewer than two InService workers after 20 minutes")
    c.kube("delete deployment nt-eval --ignore-not-found")  # left over from a stopped run
    for w in ws[:2]:
        if not until(lambda: c.healthy(w), 15, 15):
            if again:
                raise RuntimeError(f"{w} not healthy after 15 minutes")
            # left changed by a stopped run, or held by the controller: start again on a fresh node
            log(f"{w} is not healthy; replacing it")
            replace(c, w, False)
            return prepare(c, again=True)
    return ws[0], ws[1]


def replace(c, node, contained):
    """Removes worker 1 so the next run gets a fresh node."""
    if contained:
        ok, out = ssm(c.cpid, f"nodetrust-controller terminate -instance {node} -yes", timeout=120)
        log(f"terminate {node}: {out.strip()[-200:]}")
    else:
        name = c.node_name(node)
        aws("autoscaling", "terminate-instance-in-auto-scaling-group", "--instance-id", node,
            "--no-should-decrement-desired-capacity")
        if name:
            c.kube(f"delete node {name} --ignore-not-found --wait=false")
    sh(["aws", "--region", REGION, "ec2", "wait", "instance-terminated", "--instance-ids", node], check=False)


def first_event(events, after, kinds):
    for e in events:
        if ts(e["at"]) >= after - 1 and any(e["kind"] == k or e["kind"].startswith(k) for k in kinds):
            return e
    return None


def pods_moved(c, node_name, t_start):
    """Seconds until the nt-eval pods are all Running on other nodes."""
    def done():
        out = c.kube("get pods -l app=nt-eval -o jsonpath='{range .items[*]}{.spec.nodeName} {.status.phase} {.metadata.deletionTimestamp}{\"\\n\"}{end}'")
        rows = [l.split(" ") for l in out.splitlines() if l.strip()]
        live = [r for r in rows if len(r) >= 2 and r[1] == "Running" and (len(r) < 3 or not r[2])]
        return len(live) >= 4 and all(r[0] != node_name for r in live)
    if until(done, 10, 5):
        return round(time.time() - t_start, 1)
    return None


def steps(r, t_find):
    """Containment step times from the controller's record. Cordon counts from
    the verifier's finding; the AWS steps count from the operator's approval
    (or the finding, if the breaker did not hold the node), on the
    controller's own clock."""
    ev = {}
    for x in r.get("events", []):
        ev.setdefault(x["text"].split(":")[0].split(" (")[0], ts(x["at"]))
    t_ok = next((t for text, t in ev.items() if text.startswith("operator approved")), t_find)
    def step(prefix, base):
        for text, t in ev.items():
            if text.startswith(prefix):
                return round(t - base, 1)
        return ""
    return dict(cordon_s=step("cordoned", t_find), isolate_s=step("isolate", t_ok),
                snapshot_s=step("snapshot", t_ok), replace_s=step("replace", t_ok),
                release_s=step("release workloads", t_ok))


def restep():
    """Recomputes the step times of contained runs from raw/ (for rows written
    before the approval time was read from the controller)."""
    rows = list(csv.DictReader(open(RUNS_CSV)))
    for row in rows:
        if row["result"] == "prevented" and "RAN-" not in row["notes"]:
            # match means the kernel refused it; a measured attempt is noted, not a failure
            flagged = row["tier"] not in ("healthy", "")
            if flagged and "attempt measured" not in row["notes"]:
                row["notes"] = "attempt measured; " + row["notes"]
            row.update(match=True, baseline_untrusted=flagged, nodes_lost_baseline=1 if flagged else 0)
            continue
        d = os.path.join(RAW, f"{row['scenario']}-{row['run']}")
        if row["contained"] != "True" or not os.path.exists(os.path.join(d, "controller.json")):
            continue
        r = json.load(open(os.path.join(d, "controller.json")))
        tr = json.load(open(os.path.join(d, "track.json")))
        e = first_event(tr.get("history") or [], ts(row["t_used"]), ["critical"])
        if e:
            row.update(steps(r, ts(e["at"])))
            print(row["scenario"], row["run"], {k: row[k] for k in ("cordon_s", "isolate_s", "snapshot_s", "replace_s", "release_s")})
    with open(RUNS_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)


def run_one(c, sid, n):
    sc = SCENARIOS[sid]
    w1, w2 = prepare(c)
    raw = os.path.join(RAW, f"{sid}-{n}")
    os.makedirs(raw, exist_ok=True)
    row = {k: "" for k in FIELDS}
    row.update(scenario=sid, run=n, worker=w1, started=iso(time.time()), kind=sc["kind"],
               expected=json.dumps(sc.get("expect", "prevented")))
    log(f"{sid} run {n} on {w1}: {sc['what']}")
    node_name = c.node_name(w1)

    if sc.get("pods"):
        c.kube("create deployment nt-eval --image=registry.k8s.io/pause:3.10 --replicas=4 2>/dev/null; "
               f"{K} rollout status deployment/nt-eval --timeout=180s")
        on_w1 = c.kube("get pods -l app=nt-eval -o wide").count(node_name or "none")
        row["notes"] = f"{on_w1} of 4 pods on worker 1 before; "

    # 2. inject
    if "steps" in sc:
        t0 = None
        for i, f in enumerate(sc["steps"]):
            ok, out = ssm(w1, f"echo '# nodetrust A11' >>{f} && cat {f} >/dev/null && {NOW}")
            t = float(out.strip().split("T=")[-1])
            t0 = t0 or t
            last = t
            if i < len(sc["steps"]) - 1:
                time.sleep(sc["every"])
        t_used = last
    else:
        ok, out = ssm(w1, sc["cmd"])
        open(os.path.join(raw, "inject.txt"), "w").write(out)
        if "T=" not in out:
            row.update(result="inject-failed", notes=row["notes"] + out.strip()[-200:])
            return row
        t_used = float(out.split("T=")[-1].split()[0])
    row["t_used"] = iso(t_used)

    # 3. finding
    if sc["kind"] == "prevented":
        refused = "REFUSED" in out and "RAN-" not in out
        time.sleep(150)  # two cycles: anything the attempt left in the IMA log is scored by then
        n1 = c.verifier([w1]).get(w1, {})
        # prevented = the kernel refused to run it. The attempt can still leave
        # a measurement (ld.so maps the file before the noexec check fails),
        # which the verifier then scores: that is recorded, not a failure.
        flagged = n1.get("tier") != "healthy"
        row.update(result="prevented" if refused else "ran", match=refused,
                   finding=" ".join(f'{f["class"]}:{f["path"]}' for f in n1.get("files") or []),
                   score=n1.get("score"), tier=n1.get("tier"), nodes_lost=0,
                   nodes_lost_baseline=1 if flagged else 0, baseline_untrusted=flagged,
                   notes=row["notes"] + ("attempt measured; " if flagged else "") + out.strip().replace("\n", " ")[-160:])
        json.dump(n1, open(os.path.join(raw, "verifier.json"), "w"), indent=1)
        if flagged:
            replace(c, w1, False)  # the next run needs a clean worker
        return row  # otherwise worker 1 is unchanged and stays

    def found():
        n1 = c.verifier([w1]).get(w1, {})
        if sc["kind"] == "critical":
            return n1 if n1.get("critical") else None
        want = sc["expect"][0]
        return n1 if n1.get("score", 100) <= want else None
    n1 = until(found, sc["timeout"], 5)
    tr = c.track(w1) if n1 else {}
    json.dump(tr, open(os.path.join(raw, "track.json"), "w"), indent=1)
    if not n1:
        row.update(result="not-detected", match=False)
        replace(c, w1, False)
        return row
    events = tr.get("history") or []
    if sc["kind"] == "critical":
        finds = n1.get("findings") or []
        types = [f["type"] for f in finds]
        e = first_event(events, t_used, ["critical"])
        row.update(finding=" ".join(f'{f["type"]}:{f.get("path", "")}' for f in finds), result="critical",
                   match=sc["expect"] in types, score=n1.get("score"), tier=n1.get("tier"))
    else:
        if sc["kind"] == "score" and sid == "A11":
            until(lambda: c.verifier([w1])[w1]["score"] <= 80, 3, 5)
            n1 = c.verifier([w1])[w1]
            tr = c.track(w1)
            events = tr.get("history") or []
        e = first_event(events, t_used, ["drift-"])
        drift = e["kind"].replace("drift-", "") if e else ""
        if sid == "A11":
            drifts = [x["kind"].replace("drift-", "") for x in events if x["kind"].startswith("drift-") and ts(x["at"]) >= t0 - 1]
            drift = drifts[-1] if drifts else ""
            row["notes"] += "drift classes " + " ".join(drifts) + "; "
        want = sc["expect"]
        row.update(result="score", finding=" ".join(f'{f["class"]}:{f["path"]}' for f in n1.get("files") or []),
                   score=n1.get("score"), tier=n1.get("tier"), drift=drift,
                   match=n1.get("score") == want[0] and n1.get("tier") == want[1] and drift == want[2])
    if e:
        row["detect_s"] = round(ts(e["at"]) - t_used, 1)
    t_find = ts(e["at"]) if e else time.time()
    # baseline (12.4): any mismatch or critical finding -> untrusted, NoExecute taint
    row["baseline_untrusted"] = True
    row["nodes_lost_baseline"] = 1

    # 4. containment
    contained = False
    if sc["kind"] == "critical":
        def rec():
            r = c.controller(w1)
            return r if r and r.get("phase") else None
        r = until(rec, 3, 5)
        if r and r["phase"] == "held":
            row["held"] = True
            ssm(c.cpid, f"nodetrust-controller approve -instance {w1}", timeout=60)
        else:
            row["held"] = False
        t_rel = time.time()
        r = until(lambda: (lambda x: x if x and x.get("phase") == "released" else None)(c.controller(w1)), 5, 5)
        contained = bool(r)
        if r:
            row.update(contained=True, **steps(r, t_find))
            json.dump(r, open(os.path.join(raw, "controller.json"), "w"), indent=1)
            if sc.get("pods"):
                row["pods_moved_s"] = pods_moved(c, node_name, t_rel)
        row["nodes_lost"] = 1 if contained else 0
    else:
        row["nodes_lost"] = 0
        row["contained"] = False
    json.dump(n1, open(os.path.join(raw, "verifier.json"), "w"), indent=1)

    # 5. next run on a fresh worker
    if sc.get("pods"):
        c.kube("delete deployment nt-eval --ignore-not-found")
    replace(c, w1, contained)
    return row


def append(row):
    new = not os.path.exists(RUNS_CSV)
    with open(RUNS_CSV, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)


# --- report ---------------------------------------------------------------------------------

def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return ""
    k = (len(xs) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(xs) - 1)
    return round(xs[lo] + (xs[hi] - xs[lo]) * (k - lo), 1)


def report(path_out):
    allrows = list(csv.DictReader(open(RUNS_CSV)))
    bad = [r for r in allrows if r["result"] in ("inject-failed", "error")]
    rows = [r for r in allrows if r not in bad]
    by = {}
    for r in rows:
        by.setdefault(r["scenario"], []).append(r)
    num = lambda rs, k: [float(r[k]) for r in rs if r[k] not in ("", "None")]
    out = ["# Phase 7 results", "",
           f"From {len(rows)} runs in runs.csv; times in seconds, median and 95th percentile.", "",
           "| Scenario | Runs | As expected | Result | Detection (med / p95) | Cordon | Isolate | Release | Nodes lost (ours / binary) |",
           "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    order = sorted(by, key=lambda s: int(s[1:]))
    for s in order:
        rs = by[s]
        ok = sum(r["match"] == "True" for r in rs)
        res = sorted({(r["result"] + (" " + r["tier"] if r["result"] == "score" else "")) for r in rs})
        f = lambda k: (f"{pct(num(rs, k), .5)} / {pct(num(rs, k), .95)}" if num(rs, k) else "")
        lost = sum(int(r["nodes_lost"] or 0) for r in rs)
        lostb = sum(int(r["nodes_lost_baseline"] or 0) for r in rs)
        out.append(f"| {s} | {len(rs)} | {ok}/{len(rs)} | {', '.join(res)} | "
                   f"{f('detect_s')} | {f('cordon_s')} | {f('isolate_s')} | "
                   f"{f('release_s')} | {lost} / {lostb} |")
    out += ["", "Not run live:", ""] + [f"- {k}: {v}" for k, v in NOT_LIVE.items()]
    if bad:
        out += ["", "Runs not counted (the runner or the cluster failed, not the scenario):", ""] + \
            [f"- {r['scenario']} run {r['run']}: {r['result']}: {r['notes'][:150]}" for r in bad]
    out += ["", "Detection is from the moment the changed file was used (worker clock) to the verifier's",
            "finding (verifier clock). Cordon is from the finding; isolate and release are from the",
            "operator's approval when the circuit breaker held (two workers: one critical node is 50%).",
            "The binary baseline (blueprint 12.4) marks a node untrusted on any mismatch."]
    open(path_out, "w").write("\n".join(out) + "\n")
    print("\n".join(out))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("scenarios", nargs="+")
    r.add_argument("--runs", type=int, default=1)
    sub.add_parser("list")
    sub.add_parser("report")
    sub.add_parser("restep")
    a = ap.parse_args()
    if a.cmd == "list":
        for k, v in SCENARIOS.items():
            print(f"{k:4} {v['kind']:9} {str(v.get('expect', '')):28} {v['what']}")
        for k, v in NOT_LIVE.items():
            print(f"{k:4} {'not live':9} {'':28} {v}")
        return
    if a.cmd == "restep":
        restep()
        return
    if a.cmd == "report":
        report(os.path.join(HERE, "results.md"))
        return
    for s in a.scenarios:
        if s not in SCENARIOS:
            sys.exit(f"unknown scenario {s} (see: ./evaluate.py list)")
    c = Cluster()
    for n in range(1, a.runs + 1):
        for s in a.scenarios:
            existing = [r for r in csv.DictReader(open(RUNS_CSV))] if os.path.exists(RUNS_CSV) else []
            k = 1 + sum(1 for r in existing if r["scenario"] == s)
            try:
                row = run_one(c, s, k)
            except Exception as e:  # record and go on with the next run
                row = {f: "" for f in FIELDS}
                row.update(scenario=s, run=k, started=iso(time.time()), result="error",
                           notes=f"{type(e).__name__}: {e}"[-300:])
                log(f"{s} run {k} error: {traceback.format_exc()[-1500:]}")
            append(row)
            msg = (f"{s} run {k}: {row['result']} match={row['match']} detect={row['detect_s']}s "
                   f"score={row['score']} tier={row['tier']} {row['finding'][:80]}")
            if row.get("kind") == "critical" and row["result"] == "critical":
                # critical findings skip scoring (blueprint 7.2), so the score stays as it was
                msg += (f"\n    contained={row['contained']} held={row['held']} cordon={row['cordon_s']}s "
                        f"isolate={row['isolate_s']}s snapshot={row['snapshot_s']}s "
                        f"replace={row['replace_s']}s release={row['release_s']}s")
                if row.get("pods_moved_s") not in ("", None):
                    msg += f" pods_moved={row['pods_moved_s']}s"
            log(msg)


if __name__ == "__main__":
    main()
