#!/usr/bin/env bash
# Runs on a worker as root through SSM; check-node.sh ships it together with
# ima_snapshot.py and ima_replay.py.
#
# Usage: check-node-remote.sh <ami-id> <instance-id>
#
#   1. snapshot A: the attested IMA measurements as the node is now
#   2. tamper on purpose:
#        - add /usr/local/bin/nt-evil (a copy of true with bytes appended) and run it
#        - append bytes to /usr/bin/whoami, a file in the manifest, and run it
#   3. snapshot B
#
# The node is left tampered; it is a throwaway cluster worker.
set -euo pipefail
AMI="$1" IID="$2"
cd "$(dirname "$0")"
OUT=/root/nt-ima
install -d -m 0700 "$OUT"

pass() { printf 'PASS %-26s %s\n' "$1" "$2"; }
fail() { printf 'FAIL %-26s %s\n' "$1" "$2"; }
info() { printf 'INFO %-26s %s\n' "$1" "$2"; }

snap() { # snap <label>
	local out
	if out="$(python3 ima_snapshot.py --out "$OUT/$1.tsv.gz" --meta "ami=$AMI" --meta "instance=$IID" --meta "label=$1")"; then
		pass "snapshot-$1" "$out"
	else
		fail "snapshot-$1" "$out"
		exit 1
	fi
	info "snapshot-$1-file" "$(stat -c %s "$OUT/$1.tsv.gz") bytes sha256 $(sha256sum "$OUT/$1.tsv.gz" | cut -d' ' -f1)"
}

info node "$(uname -r), up $(cut -d. -f1 /proc/uptime) s, $(wc -l </sys/kernel/security/ima/ascii_runtime_measurements) IMA entries"
snap A

# --- tamper -------------------------------------------------------------------------
install -m 0755 /usr/bin/true /usr/local/bin/nt-evil
printf 'nodetrust-step-2.4-tamper' >>/usr/local/bin/nt-evil
/usr/local/bin/nt-evil
printf '\0nodetrust-step-2.4-tamper' >>/usr/bin/whoami
/usr/bin/whoami >/dev/null
ascii=/sys/kernel/security/ima/ascii_runtime_measurements
for f in /usr/local/bin/nt-evil /usr/bin/whoami; do
	h="$(sha256sum "$f" | cut -d' ' -f1)"
	if grep -qF "sha256:$h $f" "$ascii"; then
		pass "tamper-measured" "$f (sha256 ${h:0:16}...) is in the IMA log"
	else
		fail "tamper-measured" "$f with its new hash is not in the IMA log"
	fi
done

snap B
