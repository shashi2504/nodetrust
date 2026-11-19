#!/usr/bin/env bash
# Why did dbx change across a reboot? Collects, from one worker over SSM:
# the Secure Boot variables (size, time, hash), what touched them in the
# previous boot's journal, the packages that can write them, and the dbx
# event of the current boot's TCG log.
# Usage: ./diag-dbx.sh <instance-id>
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=../phase1/lib.sh
. ../phase1/lib.sh
need aws
IID="${1:?usage: $0 <instance-id>}"
REGION="$(region)"
aws_ready
OUT="$PWD/diag-dbx-$IID-$(date +%H%M%S).txt"
run_ssm_json "$REGION" "$IID" '
echo "== uptime / boots"; uptime; journalctl --list-boots --no-pager | tail -3
echo "== efivars (size, mtime, sha256 of the data after the 4-byte attributes)"
for v in /sys/firmware/efi/efivars/{PK,KEK,db,dbx,SbatLevel,SbatLevelRT,MokListRT,MokListXRT,dbDefault,dbxDefault}-*; do
  [ -e "$v" ] || continue
  printf "%-60s %8s %s %s\n" "$(basename "$v")" "$(stat -c %s "$v")" "$(stat -c %y "$v" | cut -c1-19)" "$(tail -c +5 "$v" | sha256sum | cut -c1-16)"
done
echo "== previous boot: lines about dbx / secure boot / efi variables / fwupd / shim"
journalctl -b -1 --no-pager -o short-iso 2>/dev/null | grep -iE "dbx|secure ?boot|efivar|efi: |fwupd|shim|sbat|mok|uefi" | tail -40
echo "== current boot: same"
journalctl -b 0 --no-pager -o short-iso | grep -iE "dbx|secure ?boot|efivar|fwupd|shim|sbat|mok|uefi" | tail -25
echo "== units"
for u in fwupd.service fwupd-refresh.timer secureboot-db.service; do printf "%-28s %s\n" "$u" "$(systemctl is-enabled "$u" 2>&1)"; done
echo "== packages"
dpkg -l | awk "/secureboot|fwupd|shim|sbsigntool|efitools|mokutil/ {print \$2, \$3}"
ls -l /usr/share/secureboot/updates 2>/dev/null | head; ls /usr/share/secureboot 2>/dev/null
echo "== dbx events in this boot (PCR 7)"
tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements 2>/dev/null | grep -B3 -A12 "UnicodeName: dbx" | grep -E "Digest|VariableDataLength|UnicodeName" | head -12
' >"$OUT" || { cat "$OUT"; die "SSM command failed"; }
cat "$OUT"
log "saved $OUT"
