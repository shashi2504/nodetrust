# shellcheck shell=bash
# Helpers for the phase 4 checks: read the verifier's status.json over SSM
# and wait for a node to reach a condition. Needs REGION, VID and OUT.

# node <instance>: one line
#   "tier score critical unattested state | events | reason | files | findings | key=value ..."
# A failed SSM call (the laptop can lose the endpoint for a moment) is
# retried; if the status still cannot be read the line starts with "- 0".
node() {
	for _ in 1 2 3; do
		if run_ssm_json "$REGION" "$VID" "cat /var/lib/nodetrust-verifier/status.json" 2>>"$OUT/ssm-errors.txt" |
			sed -n '/^{/,$p' >"$OUT/status.json" && [ -s "$OUT/status.json" ]; then
			break
		fi
		sleep 10
	done
	if ! [ -s "$OUT/status.json" ]; then
		echo "- 0 false false no-status | | could not read status.json (see ssm-errors.txt) | | |"
		return 0
	fi
	cp "$OUT/status.json" "$OUT/status-$(date +%H%M%S).json"
	python3 - "$OUT/status.json" "$1" <<'PY_EOF'
import json, sys
for n in json.load(open(sys.argv[1]))["nodes"]:
    if n["instance_id"] == sys.argv[2]:
        ev = " ".join(e["kind"] for e in n.get("recent") or [])
        files = " ".join(f'{f["class"]}:{f["path"]}' for f in n.get("files") or [])
        finds = " ".join(f'{f["type"]}:{f.get("path","")}' for f in n.get("findings") or [])
        v = n.get("verdict") or {}
        sw = v.get("sweep") or {}
        x = {"canary": v.get("canary", "-"), "boot": v.get("boot", "-"), "new": v.get("new", 0),
             "sweep": sw.get("opened", 0), "partial": str(sw.get("partial", False)).lower(),
             "mountns": v.get("mount_namespaces", 0), "interval": int(n.get("interval_s", 0)),
             "entries": n.get("ima_entries", 0), "cycles": n.get("cycles", 0)}
        xs = " ".join(f"{k}={val}" for k, val in x.items())
        print(f'{n.get("tier") or "-"} {n.get("score",0):g} {str(n.get("critical",False)).lower()} '
              f'{str(n.get("unattested",False)).lower()} {n["state"]} | {ev} | {n.get("reason","")[:160]} | {files} | {finds} | {xs}')
        break
else:
    print("- 0 false false not-listed | | not in status.json | | |")
PY_EOF
}

# wait_for <instance> <minutes> <python condition>
# The condition sees: tier, score, crit, unatt, state, events (list), files
# (str), finds (str), reason (str), x (dict of the key=value part: canary,
# boot, new, sweep, partial, mountns, interval, entries, cycles) and num(key).
wait_for() {
	local deadline=$((SECONDS + $2 * 60)) line
	while :; do
		line="$(node "$1")"
		if python3 -c '
import sys
parts = ([p.strip() for p in sys.argv[1].split("|")] + [""] * 6)[:6]
f = parts[0].split()
tier, score, crit, unatt, state = f[0], float(f[1]), f[2] == "true", f[3] == "true", f[4]
events, reason, files, finds = parts[1].split(), parts[2], parts[3], parts[4]
x = dict(kv.split("=", 1) for kv in parts[5].split() if "=" in kv)
num = lambda k: int(x.get(k, "0") or 0)
sys.exit(0 if eval(sys.argv[2]) else 1)' "$line" "$3"; then
			echo "$line"
			return 0
		fi
		[ "$SECONDS" -lt "$deadline" ] || break
		sleep 15
	done
	echo "$line"
	return 1
}

# check <name> <instance> <minutes> <condition>: PASS or FAIL with the line.
check() {
	local l
	if l="$(wait_for "$2" "$3" "$4")"; then pass "$1" "$l"; else fail "$1" "$l"; fi
}
