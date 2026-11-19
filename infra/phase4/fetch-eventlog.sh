#!/usr/bin/env bash
# Step 4.1a: fetch the TCG boot event log from a golden-AMI instance.
#
# Collects, over SSM:
#   binary_bios_measurements   the raw event log (what the verifier will parse)
#   eventlog.yaml              tpm2_eventlog's reading of it (a second parser to compare with)
#   pcrs.txt                   the live SHA-256 PCRs 0-9 (what the log must replay to)
#   boot-files.txt             SHA-256 of the files the boot chain loads (shim, GRUB, kernel, initrd, grub.cfg)
#
# Usage: ./fetch-eventlog.sh <instance-id>     (e.g. a probe from 02-launch-probe.sh)
# Writes eventlog-<instance>-<time>/ here.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws base64 sha256sum

IID="${1:-}"
[ -n "$IID" ] || die "usage: $0 <instance-id>"
REGION="$(region)"
aws_ready
OUT="$PWD/eventlog-$IID-$(date +%Y%m%d%H%M)"
mkdir -p "$OUT"
log "waiting for SSM on $IID"
wait_ssm_online "$REGION" "$IID" 10 || die "$IID is not online in SSM"

S=/root/nt-eventlog
run_ssm_json "$REGION" "$IID" "set -e; install -d -m 0700 $S
cp /sys/kernel/security/tpm0/binary_bios_measurements $S/binary_bios_measurements
tpm2_eventlog $S/binary_bios_measurements >$S/eventlog.yaml 2>&1 || true
tpm2_pcrread sha256:0,1,2,3,4,5,6,7,8,9 >$S/pcrs.txt
( cd /boot && sha256sum vmlinuz-* initrd.img-* grub/grub.cfg grubenv 2>/dev/null; cd /boot/efi && find . -type f -iname '*.efi' -exec sha256sum {} + ) >$S/boot-files.txt 2>&1 || true
cat /proc/cmdline >$S/cmdline.txt
mokutil --sb-state >>$S/cmdline.txt 2>&1 || true
cd $S && tar czf /root/nt-eventlog.tgz . && sha256sum /root/nt-eventlog.tgz && stat -c %s /root/nt-eventlog.tgz" >"$OUT/remote.txt" ||
	die "collection failed: $(cat "$OUT/remote.txt")"

want="$(awk '/nt-eventlog.tgz$/ { print $1 }' "$OUT/remote.txt")"
size="$(grep -E '^[0-9]+$' "$OUT/remote.txt" | tail -1)"
[[ "$size" =~ ^[0-9]+$ ]] && [ -n "$want" ] || die "could not read size and sha256: $(cat "$OUT/remote.txt")"
: >"$OUT/eventlog.tgz"
chunk=15000
for ((k = 0; k * chunk < size; k++)); do
	run_ssm_json "$REGION" "$IID" "dd if=/root/nt-eventlog.tgz bs=$chunk skip=$k count=1 status=none | base64 -w0" |
		tr -d '[:space:]' | base64 -d >>"$OUT/eventlog.tgz"
done
[ "$(sha256sum "$OUT/eventlog.tgz" | cut -d' ' -f1)" = "$want" ] || die "fetched archive does not match the node's sha256"
tar xzf "$OUT/eventlog.tgz" -C "$OUT"
log "fetched $size bytes in $k chunks into $OUT"
ls -l "$OUT"
