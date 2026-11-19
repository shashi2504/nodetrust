#!/usr/bin/env bash
# nodetrust Phase 1 platform probe.
#
# Runs as root on a NitroTPM instance booted from the Secure Boot base AMI,
# after the reboot that turns IMA on. It checks every platform assumption the
# blueprint makes and prints one line per check:
#
#   PASS / FAIL  an assumption the design depends on
#   INFO         a fact recorded for the golden-AMI and verifier work
#
# The EK comparison with the EC2 API happens on your machine in
# 03-run-probe.sh, because worker instances have no EC2 permissions.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
OUT=/root/nodetrust-probe.txt
pass=0
fail=0
: >"$OUT"

result() {
	printf '%-4s %-26s %s\n' "$1" "$2" "$3" | tee -a "$OUT"
	case "$1" in
	PASS) pass=$((pass + 1)) ;;
	FAIL) fail=$((fail + 1)) ;;
	esac
}

check() { # check <name> <detail> <command...>: PASS if the command succeeds
	local name="$1" detail="$2"
	shift 2
	if "$@" >/dev/null 2>&1; then result PASS "$name" "$detail"; else result FAIL "$name" "$detail"; fi
}

if [ "$(id -u)" -ne 0 ]; then
	echo "probe.sh must run as root" >&2
	exit 2
fi

# --golden adds the step 1.2 checks for the golden worker AMI.
MODE=base
case "${1:-}" in
"") ;;
--golden) MODE=golden ;;
*)
	echo "usage: probe.sh [--golden]" >&2
	exit 2
	;;
esac

# --- kernel ------------------------------------------------------------------
kver="$(uname -r)"
kmaj="${kver%%.*}"
kmin="${kver#*.}"
kmin="${kmin%%.*}"
if [ "$kmaj" -gt 6 ] || { [ "$kmaj" -eq 6 ] && [ "$kmin" -ge 3 ]; }; then
	result PASS kernel-version "$kver (6.3+ needed for vm.memfd_noexec)"
else
	result FAIL kernel-version "$kver (6.3+ needed for vm.memfd_noexec)"
fi
result INFO cmdline "$(cat /proc/cmdline)"

kconfig="/boot/config-$kver"
for opt in CONFIG_IMA CONFIG_IMA_WRITE_POLICY CONFIG_IMA_READ_POLICY CONFIG_IMA_APPRAISE \
	CONFIG_IMA_ARCH_POLICY CONFIG_IMA_DEFAULT_TEMPLATE CONFIG_IMA_DEFAULT_HASH \
	CONFIG_IMA_MEASURE_PCR_IDX CONFIG_SECURITY_LOCKDOWN_LSM CONFIG_LOCK_DOWN_IN_EFI_SECURE_BOOT \
	CONFIG_MODULE_SIG_FORCE; do
	val="$(grep -E "^${opt}=" "$kconfig" 2>/dev/null | cut -d= -f2- || true)"
	result INFO "$opt" "${val:-not set}"
done

# --- TPM ---------------------------------------------------------------------
check tpm-device "/dev/tpmrm0 present" test -c /dev/tpmrm0
check tpm2-tools "tpm2_pcrread available" command -v tpm2_pcrread

# Allocated banks are the ones with a non-empty PCR selection, e.g. "  - sha256: [ 0, 1, ... ]".
banks="$(tpm2_getcap pcrs 2>/dev/null | sed -nE 's/^ *- (sha1|sha256|sha384|sha512|sm3_256): \[ *[0-9].*/\1/p' | tr '\n' ' ')"
result INFO pcr-banks "${banks:-none}"
if case " $banks " in *" sha256 "*) true ;; *) false ;; esac; then
	result PASS sha256-bank "SHA-256 PCR bank allocated"
else
	result FAIL sha256-bank "SHA-256 PCR bank not allocated"
fi
manuf="$(tpm2_getcap properties-fixed 2>/dev/null | grep -A2 'TPM2_PT_MANUFACTURER' | grep -oE 'value: *"[^"]*"' | head -1)"
result INFO tpm-manufacturer "${manuf:-unknown}"

# --- Secure Boot and lockdown -------------------------------------------------
sbvar=/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c
if [ -r "$sbvar" ] && [ "$(od -An -t u1 "$sbvar" | awk '{print $NF}')" = "1" ]; then
	result PASS secure-boot "enabled (EFI SecureBoot variable = 1)"
else
	result FAIL secure-boot "not enabled"
fi
lockdown="$(cat /sys/kernel/security/lockdown 2>/dev/null || echo missing)"
if echo "$lockdown" | grep -qE '\[(integrity|confidentiality)\]'; then
	result PASS kernel-lockdown "$lockdown"
else
	result FAIL kernel-lockdown "$lockdown"
fi

# --- IMA ---------------------------------------------------------------------
for arg in ima_template=ima-ng ima_hash=sha256 ima_policy=; do
	check "cmdline:${arg%%=*}" "$arg on the kernel command line" grep -q -- "$arg" /proc/cmdline
done
imalog=/sys/kernel/security/ima/ascii_runtime_measurements
entries="$({ wc -l <"$imalog"; } 2>/dev/null || echo 0)"
if [ "$entries" -gt 1 ]; then
	result PASS ima-active "$entries measurements in the log"
else
	result FAIL ima-active "$entries measurements (only boot_aggregate means no policy is active)"
fi
if [ -e /sys/kernel/security/ima/policy ]; then
	result INFO ima-policy-file "$(stat -c '%A' /sys/kernel/security/ima/policy)"
fi

# The design depends on the SHA-256 bank (PASS/FAIL); other banks are recorded as INFO.
for bank in sha256 sha384 sha1; do
	case " $banks " in *" $bank "*) ;; *) continue ;; esac
	if python3 -I "$DIR/ima_replay.py" --bank "$bank" >"/root/ima-replay-$bank.json" 2>&1; then
		status=PASS
		detail="log replay equals PCR 10, see /root/ima-replay-$bank.json"
	else
		status=FAIL
		detail="$(tr -d '\n' <"/root/ima-replay-$bank.json" | cut -c1-200)"
	fi
	if [ "$bank" != sha256 ]; then
		detail="$status: $detail"
		status=INFO
	fi
	result "$status" "ima-replay-$bank" "$detail"
done

# --- hardening prerequisites ---------------------------------------------------
if [ -f /proc/sys/vm/memfd_noexec ]; then
	result PASS memfd-noexec-sysctl "present, current value $(cat /proc/sys/vm/memfd_noexec)"
else
	result FAIL memfd-noexec-sysctl "missing"
fi
check modules-disabled-sysctl "kernel.modules_disabled present" test -f /proc/sys/kernel/modules_disabled
check kexec-disabled-sysctl "kernel.kexec_load_disabled present" test -f /proc/sys/kernel/kexec_load_disabled

# --- Endorsement key ----------------------------------------------------------
tmp="$(mktemp -d)"
if tpm2_createek -c "$tmp/ek.ctx" -G rsa -u "$tmp/ek.pem" -f pem >/dev/null 2>&1 &&
	openssl pkey -pubin -in "$tmp/ek.pem" -outform DER -out "$tmp/ek.der" 2>/dev/null; then
	result PASS ek-rsa-read "RSA EK created from the default TCG template"
	echo "EK_RSA_DER_B64=$(base64 -w0 "$tmp/ek.der")" | tee -a "$OUT"
	tpm2_flushcontext "$tmp/ek.ctx" >/dev/null 2>&1 || true
else
	result FAIL ek-rsa-read "tpm2_createek -G rsa failed"
fi
rm -rf "$tmp"

# --- golden AMI checks (step 1.2) ----------------------------------------------
in_log() { grep -qF -- "$1" "$imalog"; }

if [ "$MODE" = golden ]; then
	# IMA policy: the one write per boot must already be used up by our loader.
	# Both checks below need a live IMA log; without one, "absent" proves nothing.
	if [ ! -r "$imalog" ]; then
		result FAIL ima-policy-locked "no IMA log, so the policy state cannot be judged"
	elif [ ! -e /sys/kernel/security/ima/policy ]; then
		result PASS ima-policy-locked "policy file gone, the one write per boot is used"
	else
		result FAIL ima-policy-locked "policy file still writable: root could load its own policy"
	fi
	check ima-policy-unit "nodetrust-ima-policy.service ran" systemctl is-active --quiet nodetrust-ima-policy.service
	result INFO ima-policy-load "$(journalctl -b -u nodetrust-ima-policy.service -o cat 2>/dev/null | grep -o 'loaded by [a-z]*' | tail -1)"
	check ima-policy-measured "/etc/nodetrust/ima-policy is in the IMA log" in_log /etc/nodetrust/ima-policy

	# Canary design (blueprint 10.3): a file root writes and reads on ext4 must
	# appear in the log with sha256(content).
	install -d -m 0700 /var/lib/nodetrust
	val="$(head -c 32 /dev/urandom | base64 -w0)"
	printf '%s' "$val" >/var/lib/nodetrust/canary-test
	cat /var/lib/nodetrust/canary-test >/dev/null
	h="$(printf '%s' "$val" | sha256sum | cut -d' ' -f1)"
	check canary-measured "root read on ext4 logged with sha256(content)" in_log "sha256:$h /var/lib/nodetrust/canary-test"

	# Reads on tmpfs are out of policy, which also shows tcb was replaced.
	val="$(head -c 32 /dev/urandom | base64 -w0)"
	printf '%s' "$val" >/run/nodetrust-tmpfs-test
	cat /run/nodetrust-tmpfs-test >/dev/null
	h="$(printf '%s' "$val" | sha256sum | cut -d' ' -f1)"
	if [ ! -r "$imalog" ]; then
		result FAIL tmpfs-read-skipped "no IMA log"
	elif in_log "sha256:$h"; then
		result FAIL tmpfs-read-skipped "a root read on tmpfs was measured: the tcb policy is still active"
	else
		result PASS tmpfs-read-skipped "root reads on tmpfs are not measured (custom policy active)"
	fi
	rm -f /run/nodetrust-tmpfs-test

	# Sweep coverage (blueprint 10.2): /boot (ext4) and the EFI partition (vfat).
	cat "/boot/vmlinuz-$kver" >/dev/null 2>&1 || true
	check boot-read-measured "/boot/vmlinuz-$kver read is logged" in_log "/boot/vmlinuz-$kver"
	shim="$(find /boot/efi/EFI -iname 'shimx64.efi' 2>/dev/null | head -1)"
	if [ -n "$shim" ]; then
		cat "$shim" >/dev/null
		check esp-read-measured "$shim read is logged" in_log "$shim"
	else
		result FAIL esp-read-measured "no shimx64.efi found under /boot/efi/EFI"
	fi

	# Sysctls (blueprint 6.5).
	sysctl_is() { [ "$(sysctl -n "$1" 2>/dev/null)" = "$2" ]; }
	check sysctl-memfd_noexec "vm.memfd_noexec = 2" sysctl_is vm.memfd_noexec 2
	check sysctl-kexec "kernel.kexec_load_disabled = 1" sysctl_is kernel.kexec_load_disabled 1
	check sysctl-unpriv-bpf "kernel.unprivileged_bpf_disabled = 1" sysctl_is kernel.unprivileged_bpf_disabled 1
	check sysctl-bpf-jit-harden "net.core.bpf_jit_harden = 2" sysctl_is net.core.bpf_jit_harden 2
	check sysctl-ip-forward "net.ipv4.ip_forward = 1" sysctl_is net.ipv4.ip_forward 1
	check sysctl-bridge-nf "net.bridge.bridge-nf-call-iptables = 1" sysctl_is net.bridge.bridge-nf-call-iptables 1

	# Module lock (blueprint 10.3): preload ran cleanly, lock set, new loads refused.
	check modules-preload "systemd-modules-load loaded the whole list" systemctl is-active --quiet systemd-modules-load.service
	check modules-lock-unit "nodetrust-modules-lock.service ran" systemctl is-active --quiet nodetrust-modules-lock.service
	check sysctl-modules-disabled "kernel.modules_disabled = 1" sysctl_is kernel.modules_disabled 1
	probe_mod=""
	for m in dummy tun sctp nbd ifb; do
		if modinfo -n "$m" >/dev/null 2>&1 && ! lsmod | awk '{print $1}' | grep -qx "$m"; then
			probe_mod="$m"
			break
		fi
	done
	if [ -z "$probe_mod" ]; then
		result FAIL modules-load-refused "no unloaded test module found to try"
	elif modprobe "$probe_mod" 2>/dev/null; then
		result FAIL modules-load-refused "modprobe $probe_mod succeeded after the lock"
	else
		result PASS modules-load-refused "modprobe $probe_mod refused"
	fi

	# memfd execution (scenario A14 preview): an executable memfd must be refused.
	if python3 -I -c 'import os,sys
try:
    os.memfd_create("nt", 0x0010)  # MFD_EXEC
except OSError:
    sys.exit(0)
sys.exit(1)' 2>/dev/null; then
		result PASS memfd-exec-create "memfd_create(MFD_EXEC) refused"
	else
		result FAIL memfd-exec-create "memfd_create(MFD_EXEC) allowed"
	fi
	# The payload is /usr/bin/false: if the exec succeeds the process exits 1
	# (FAIL); only a refused exec reaches sys.exit(0) (PASS).
	if python3 -I -c 'import os,sys
fd = os.memfd_create("nt", 0)
os.write(fd, open("/usr/bin/false", "rb").read())
try:
    os.execv(f"/proc/self/fd/{fd}", ["nt"])
except OSError:
    sys.exit(0)' 2>/dev/null; then
		result PASS memfd-exec-run "exec of a memfd refused"
	else
		result FAIL memfd-exec-run "exec of a memfd was not refused"
	fi

	# noexec scratch directories (scenario A17 preview).
	for m in /tmp /var/tmp /dev/shm; do
		if findmnt -no OPTIONS "$m" 2>/dev/null | grep -qw noexec; then
			result PASS "noexec:$m" "mounted noexec"
		else
			result FAIL "noexec:$m" "not mounted noexec ($(findmnt -no OPTIONS "$m" 2>/dev/null || echo 'not a mount'))"
		fi
	done
	cp /usr/bin/true /dev/shm/nt-true && chmod 0755 /dev/shm/nt-true
	if /dev/shm/nt-true 2>/dev/null; then
		result FAIL shm-exec "binary in /dev/shm ran"
	else
		result PASS shm-exec "binary in /dev/shm refused"
	fi
	if /lib64/ld-linux-x86-64.so.2 /dev/shm/nt-true 2>/dev/null; then
		result FAIL shm-ldso-exec "ld.so ran a binary from /dev/shm"
	else
		result PASS shm-ldso-exec "ld.so refused a binary from /dev/shm"
	fi
	rm -f /dev/shm/nt-true

	# Immutability and access (blueprint 7.1, 6.5).
	if systemctl is-active --quiet ssh.service || systemctl is-active --quiet ssh.socket; then
		result FAIL ssh-off "ssh is running"
	else
		result PASS ssh-off "ssh service and socket not running"
	fi
	unit_masked() { [ "$(systemctl is-enabled "$1" 2>/dev/null)" = masked ]; }
	not_installed() { ! dpkg -s "$1" >/dev/null 2>&1; }
	all_held() {
		local held p
		held="$(apt-mark showhold)"
		for p in "$@"; do echo "$held" | grep -qx "$p" || return 1; done
	}
	check ssh-masked "ssh.service masked" unit_masked ssh.service
	check no-unattended-upgrades "unattended-upgrades not installed" not_installed unattended-upgrades
	check apt-timers-masked "apt-daily timers masked" unit_masked apt-daily-upgrade.timer
	check fwupd-masked "fwupd and its refresh timer masked" sh -c 'systemctl is-enabled fwupd.service 2>/dev/null | grep -qx masked && systemctl is-enabled fwupd-refresh.timer 2>/dev/null | grep -qx masked'
	check motd-news-masked "motd-news timer masked" sh -c 'systemctl is-enabled motd-news.timer 2>/dev/null | grep -qx masked'
	check no-hotplug-hook "cloud-init network hotplug off, no udev hook installed" \
		sh -c '! test -e /etc/udev/rules.d/90-cloud-init-hook-hotplug.rules && ! cloud-init devel hotplug-hook -s net query 2>/dev/null | grep -qx enabled'
	# dbx must come with the image: if secureboot-db has to insert Ubuntu's
	# dbx update at boot, PCR 7 differs between a worker's first and second boot.
	check dbx-in-image "dbx already has Ubuntu's update (sbkeysync inserted nothing in any boot)" \
		sh -c '! journalctl -t sbkeysync --no-pager 2>/dev/null | grep -q "Inserting key update"'
	result INFO dbx-size "$(stat -c %s /sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f 2>/dev/null || echo missing) bytes"
	result INFO timers "$(systemctl list-timers --all --no-legend 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) print $i}' | sort -u | tr '\n' ' ')"
	check snap-refresh-held "snap refreshes held" sh -c 'snap get system refresh.hold 2>/dev/null | grep -q .'
	check no-compilers "no gcc, cc or make" sh -c '! command -v gcc && ! command -v cc && ! command -v make'
	check k8s-held "kubelet, kubeadm, kubectl, containerd, runc held" all_held kubelet kubeadm kubectl containerd runc
	check containerd-systemd-cgroup "SystemdCgroup = true" grep -q 'SystemdCgroup = true' /etc/containerd/config.toml
	check kubelet-enabled "kubelet enabled" systemctl is-enabled --quiet kubelet
	result INFO versions "$(tr '\n' ' ' </etc/nodetrust/build-info 2>/dev/null)"

	# One kernel only, and it is the one running (manifest can't vouch for others).
	kernels="$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f ' 2>/dev/null)"
	if [ "$kernels" = "vmlinuz-$(uname -r) " ]; then
		result PASS single-kernel "only /boot/vmlinuz-$(uname -r), the running kernel"
	else
		result FAIL single-kernel "running $(uname -r), /boot has: ${kernels:-nothing}"
	fi
	if [ "$(grep -c '^[[:space:]]*linux[[:space:]]' /boot/grub/grub.cfg 2>/dev/null)" -gt 0 ] &&
		! grep -E '^[[:space:]]*linux[[:space:]]' /boot/grub/grub.cfg | grep -vq "vmlinuz-$(uname -r)"; then
		result PASS grub-single-kernel "every GRUB entry boots $(uname -r)"
	else
		result FAIL grub-single-kernel "grub.cfg has entries for other kernels"
	fi

	# nodetrust agent (Phase 3, step 3.3).
	agent=/usr/local/bin/nodetrust-agent
	want_sha="$(sed -n 's/^agent_sha256=//p' /etc/nodetrust/build-info 2>/dev/null)"
	if [ -n "$want_sha" ] && [ "$(sha256sum "$agent" 2>/dev/null | cut -d' ' -f1)" = "$want_sha" ]; then
		result PASS agent-binary "$agent matches agent_sha256 in build-info"
	else
		result FAIL agent-binary "$agent missing or not the built binary"
	fi
	check agent-service "nodetrust-agent.service active" systemctl is-active --quiet nodetrust-agent.service
	check agent-listening "listening on TCP 9443" sh -c "ss -Hltn 'sport = :9443' | grep -q ."
	# One capability only: CAP_SYS_PTRACE, to read other processes' mount
	# namespaces for the mount audit (blueprint 10.3).
	caps="$(systemctl show -p CapabilityBoundingSet --value nodetrust-agent.service)"
	if [ "$caps" = "cap_sys_ptrace" ]; then
		result PASS agent-capabilities "only cap_sys_ptrace (mount audit)"
	else
		result FAIL agent-capabilities "capability bounding set: ${caps:-empty}"
	fi
	pid="$(systemctl show -p MainPID --value nodetrust-agent.service)"
	if [ -n "$pid" ] && [ "$pid" != 0 ] && grep -q '^CapEff:[[:space:]]*0000000000080000$' "/proc/$pid/status"; then
		result PASS agent-effective-caps "effective set is CAP_SYS_PTRACE only"
	else
		result FAIL agent-effective-caps "$(grep '^Cap' "/proc/$pid/status" 2>/dev/null | tr '\n' ' ')"
	fi
	if curl -sk --max-time 5 -X POST -o /dev/null https://127.0.0.1:9443/v1/enroll; then
		result FAIL agent-refuses-anonymous "answered a request without a client certificate"
	else
		result PASS agent-refuses-anonymous "a request without a verifier client certificate is refused"
	fi
	check agent-measured "agent binary is in the IMA log with its hash" in_log "sha256:$want_sha $agent"

	# runc must still start containers under vm.memfd_noexec=2 (blueprint 10.3).
	img=public.ecr.aws/docker/library/busybox:1.36
	before="$({ wc -l <"$imalog"; } 2>/dev/null || echo 0)"
	if ctr -n nodetrust-gate image pull "$img" >/dev/null 2>&1 &&
		ctr -n nodetrust-gate run --rm "$img" "gate-$$" /bin/true >/dev/null 2>&1; then
		result PASS runc-with-memfd-noexec "a container ran with vm.memfd_noexec=2 ($(runc --version 2>/dev/null | head -1))"
	else
		result FAIL runc-with-memfd-noexec "container start failed: $(ctr -n nodetrust-gate run --rm "$img" "gate2-$$" /bin/true 2>&1 | tail -1)"
	fi
	after="$({ wc -l <"$imalog"; } 2>/dev/null || echo 0)"
	result INFO container-log-growth "$((after - before)) IMA entries added by pulling and running one container"
	ctr -n nodetrust-gate image rm "$img" >/dev/null 2>&1 || true
fi

# --- boot PCR snapshot (for the reference manifest work) -----------------------
tpm2_pcrread sha256:0,1,2,3,4,5,7,8,9,10,14 2>/dev/null | sed 's/^/PCR /' | tee -a "$OUT" >/dev/null
result INFO pcr-snapshot "SHA-256 PCRs 0-5,7-10,14 saved in $OUT"

echo "SUMMARY pass=$pass fail=$fail" | tee -a "$OUT"
[ "$fail" -eq 0 ]
