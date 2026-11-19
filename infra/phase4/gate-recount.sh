#!/usr/bin/env bash
# Recount a phase4-gate.sh soak from what it saved: every sample in
# samples.jsonl must be verified (or outage), healthy, 100, with no file
# against it and no publish error, and no NodeTrust check may have failed
# (those are the "NodeTrust:" lines in bad-samples.txt).
# Usage: ./gate-recount.sh phase4-gate-YYYYMMDDHHMM
set -euo pipefail
d="${1:?usage: $0 <phase4-gate output folder>}"
python3 - "$d/samples.jsonl" <<'PY_EOF'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
bad = [r for r in rows if not (r["state"] in ("verified", "outage") and r["tier"] == "healthy"
       and r["score"] == 100 and not r["critical"] and not r["unattested"]
       and not r["files"] and not r["publish_error"])]
times = sorted({r["at"] for r in rows})
nodes = sorted({r["node"] for r in rows})
print(f"{len(times)} samples, {times[0]} to {times[-1]}, nodes {' '.join(nodes)}")
for r in bad:
    print("BAD", r["at"], r["node"], r["state"], r["tier"], r["score"], r["files"], r["findings"], r["publish_error"])
print(f"node samples not clean: {len(bad)} of {len(rows)}")
PY_EOF
n="$(grep -c '^ *NodeTrust:' "$d/bad-samples.txt" 2>/dev/null || true)"
echo "NodeTrust check failures: ${n:-0}"
