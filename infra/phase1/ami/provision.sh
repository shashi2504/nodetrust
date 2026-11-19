#!/bin/bash
# Golden worker AMI provisioning (Phase 1, step 1.2).
#
# Runs once as root on a builder instance launched from the Secure Boot +
# NitroTPM base AMI. build-golden-ami.sh embeds it in user data, fills in
# @@K8S_MINOR@@, and waits for the result marker on the serial console.
#
# What it sets up (blueprint Sections 6.4 and 6.5):
#   - all packages patched; unattended upgrades, apt timers and snap refreshes off
#   - containerd + runc, kubelet/kubeadm/kubectl pinned and held
#   - IMA: kernel arguments plus the nodetrust policy, loaded once per boot
#   - sysctls (memfd_noexec, kexec, BPF), noexec /tmp, /var/tmp, /dev/shm
#   - SSH disabled and masked, no compilers
# It ends by powering the instance off so the root disk can be snapshotted.
#
#   - kernel module loading locked late in boot, after the networking modules a
#     working worker needs are preloaded
set -euxo pipefail

K8S_MINOR="@@K8S_MINOR@@"
AGENT_URL="@@AGENT_URL@@"
AGENT_SHA256="@@AGENT_SHA256@@"
VERIFIER_CA_B64="@@VERIFIER_CA_B64@@"
export DEBIAN_FRONTEND=noninteractive
APT=(apt-get -y -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confold)
# apt-get update exits 0 when some index files fail to download ("W: Some
# index files failed to download"), and the next install then cannot find
# packages from that index (seen 2026-11-19: the ap-south-1 EC2 mirror
# answered 503 for noble, noble-updates and noble-backports for more than
# 15 minutes, and the install could not find tpm2-tools). Error-Mode=any
# makes such a failure an error. After three failed tries the build switches
# to Ubuntu's primary archive for the rest of the build. The packages are the
# same and apt checks the archive signature either way; the original
# sources file is put back before the image is sealed (section 9).
SOURCES=/etc/apt/sources.list.d/ubuntu.sources
REGIONAL_MIRROR='http://[a-z0-9-]*\.ec2\.archive\.ubuntu\.com/ubuntu/\?'
cp -a "$SOURCES" /root/ubuntu.sources.orig
apt_update() {
	local try
	for try in 1 2 3 4 5 6; do
		if "${APT[@]}" -o APT::Update::Error-Mode=any update; then
			return 0
		fi
		if [ "$try" -eq 3 ] && grep -q "$REGIONAL_MIRROR" "$SOURCES"; then
			echo "apt-get update failed 3 times on the regional EC2 mirror; switching to archive.ubuntu.com"
			sed -i "s#$REGIONAL_MIRROR#http://archive.ubuntu.com/ubuntu/#g" "$SOURCES"
			grep '^URIs:' "$SOURCES"
			continue
		fi
		echo "apt-get update failed (try $try of 6); retrying in 30 s"
		sleep 30
	done
	return 1
}

marker() { # write the result marker where the EC2 console output can see it
	echo "$1" | tee /dev/console /dev/ttyS0 >/dev/null 2>&1 || echo "$1"
}
trap 'marker "NODETRUST_BUILD_RESULT=failed line=$LINENO cmd=$BASH_COMMAND"' ERR

# --- 1. stop automatic changes, then patch everything --------------------------
systemctl stop unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer || true
"${APT[@]}" purge unattended-upgrades
systemctl mask apt-daily.service apt-daily.timer apt-daily-upgrade.service apt-daily-upgrade.timer
# Jobs that fetch data from the internet and have root read it back. On a
# worker that data is in no manifest, so the verifier sees unknown files
# (fwupd metadata from LVFS was seen on a worker, 2026-11-18). A cloud VM has
# no firmware for fwupd to update, and nobody reads the motd. Masked rather
# than purged, so removing a package cannot pull other packages out with it.
systemctl mask fwupd.service fwupd-refresh.service fwupd-refresh.timer \
	motd-news.service motd-news.timer
# cloud-init 26.x turns network hotplug on by default for EC2. At a worker's
# first boot its install_hotplug module then writes
# /etc/udev/rules.d/90-cloud-init-hook-hotplug.rules, which is in no manifest
# and which udev reads (so IMA measures it) on every boot (seen on workers,
# 2026-11-18). Workers never get network cards added while running, so
# network config is applied only for a new instance.
install -d -m 0755 /etc/cloud/cloud.cfg.d
cat >/etc/cloud/cloud.cfg.d/99-nodetrust-no-hotplug.cfg <<'CFG_EOF'
# nodetrust: no network hotplug, so cloud-init installs no udev hook
updates:
  network:
    when: ["boot-new-instance"]
CFG_EOF
chmod 0644 /etc/cloud/cloud.cfg.d/99-nodetrust-no-hotplug.cfg
apt_update
"${APT[@]}" full-upgrade

# --- 2. packages -------------------------------------------------------------------
"${APT[@]}" install containerd runc conntrack socat tpm2-tools python3 \
	curl gpg ca-certificates apt-transport-https

install -d -m 0755 /etc/apt/keyrings
curl -fsSL "https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/Release.key" |
	gpg --dearmor --yes -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${K8S_MINOR}/deb/ /" \
	>/etc/apt/sources.list.d/kubernetes.list
apt_update
"${APT[@]}" install kubelet kubeadm kubectl
apt-mark hold kubelet kubeadm kubectl containerd runc
systemctl enable kubelet

# No compilers on workers (blueprint 10.3). Purge any that came with the image.
for p in gcc g++ cpp make; do
	if dpkg -s "$p" >/dev/null 2>&1; then "${APT[@]}" purge "$p"; fi
done
"${APT[@]}" autoremove --purge

# --- 2b. one kernel only ----------------------------------------------------------
# full-upgrade installs the new kernel next to the one this builder booted.
# The old one would stay on disk and in GRUB's menu, and the reference
# manifest would then vouch for a kernel no worker should ever run. Purge
# every kernel except the newest. With DEBIAN_FRONTEND=noninteractive the
# linux-base removal check only warns about removing the running kernel.
NEWEST_KERNEL="$(linux-version list | linux-version sort --reverse | sed -n 1p)"
for v in $(linux-version list); do
	[ "$v" = "$NEWEST_KERNEL" ] && continue
	abi="${v%-aws}" # 7.0.0-1014-aws -> 7.0.0-1014, also matches the headers packages
	# Installed packages whose name ends in -<abi> or -<abi>-aws (image, modules,
	# headers, tools), so 7.0.0-1014 never matches 7.0.0-10145.
	pkgs="$(dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' "*${abi}*" 2>/dev/null | awk -v a="$abi" '
		function ends(s, t) { return length(s) >= length(t) && substr(s, length(s) - length(t) + 1) == t }
		$1 ~ /^[ih]i/ && (ends($2, "-" a) || ends($2, "-" a "-aws")) { print $2 }' || true)"
	echo "nodetrust: purging old kernel $v: $pkgs"
	# shellcheck disable=SC2086 # one word per package
	[ -z "$pkgs" ] || "${APT[@]}" purge $pkgs
	rm -rf "/lib/modules/$v" "/usr/lib/modules/$v"
done
[ "$(linux-version list)" = "$NEWEST_KERNEL" ]
[ "$(find /boot -maxdepth 1 -name 'vmlinuz-*' | wc -l)" = 1 ]
echo "nodetrust: kernel $NEWEST_KERNEL is the only one installed"

# --- 3. containerd -----------------------------------------------------------------
install -d -m 0755 /etc/containerd
containerd config default >/etc/containerd/config.toml
sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
grep -q 'SystemdCgroup = true' /etc/containerd/config.toml
cat >/etc/crictl.yaml <<'EOF'
runtime-endpoint: unix:///run/containerd/containerd.sock
image-endpoint: unix:///run/containerd/containerd.sock
timeout: 10
EOF
systemctl enable containerd

# --- 4. kernel modules and sysctls ---------------------------------------------------
# kernel.modules_disabled=1 blocks every later module load (blueprint 10.3).
# Hardware modules (ena, nvme, ...) still load normally through udev at boot.
# The networking modules below load on demand once kubelet, kube-proxy and
# Calico run, so they are preloaded early. The list was captured from a
# running worker on 2026-11-15 (Calico VXLAN, iptables dataplane), plus
# nft_ct for the Phase 5 peer-side deny. The lock itself is set late by
# nodetrust-modules-lock.service, never through sysctl.d, which runs too early.
cat >/etc/modules-load.d/nodetrust.conf <<'EOF'
# containers
overlay
veth
# bridge and VLAN stack
br_netfilter
bridge
8021q
# Calico VXLAN and its WireGuard probe
vxlan
udp_tunnel
ip6_udp_tunnel
wireguard
# netfilter core
x_tables
ip_tables
nfnetlink
nfnetlink_acct
nf_conntrack
nf_conntrack_netlink
nf_defrag_ipv4
nf_defrag_ipv6
nf_nat
nf_reject_ipv4
nf_tables
nft_chain_nat
nft_compat
nft_ct
ipt_REJECT
ipt_rpfilter
# xtables matches and targets used by kube-proxy and Calico
xt_addrtype
xt_comment
xt_conntrack
xt_CT
xt_mark
xt_MASQUERADE
xt_multiport
xt_nat
xt_nfacct
xt_set
xt_statistic
xt_tcpudp
# ipsets used by Calico policy
ip_set
ip_set_hash_ip
ip_set_hash_net
# queueing
sch_fq_codel
EOF

cat >/usr/local/sbin/nodetrust-lock-modules <<'EOF'
#!/bin/sh
# Block all further kernel module loads until the next boot.
set -eu
sysctl -w kernel.modules_disabled=1
echo "nodetrust: kernel module loading locked ($(lsmod | tail -n +2 | wc -l) modules loaded)"
EOF
chmod 0755 /usr/local/sbin/nodetrust-lock-modules

cat >/etc/systemd/system/nodetrust-modules-lock.service <<'EOF'
[Unit]
Description=Lock kernel module loading (kernel.modules_disabled=1)
# Late: after udev has loaded hardware modules, after the preload list, and
# after the container runtime and kubelet have started. Ordering only, so a
# kubelet that cannot start yet (no cluster) does not stop the lock.
After=systemd-modules-load.service systemd-udev-trigger.service network-online.target containerd.service kubelet.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/nodetrust-lock-modules

[Install]
WantedBy=multi-user.target
EOF
systemctl enable nodetrust-modules-lock.service
cat >/etc/sysctl.d/90-nodetrust.conf <<'EOF'
# nodetrust worker hardening (blueprint 6.5)
vm.memfd_noexec = 2
kernel.kexec_load_disabled = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
# Kubernetes networking
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

# --- 5. IMA ------------------------------------------------------------------------
# Early boot runs under the built-in tcb policy; the nodetrust policy replaces it
# as soon as the loader unit runs. lockdown=integrity is set explicitly even
# though Ubuntu already enforces it under Secure Boot.
cat >/etc/default/grub.d/60-nodetrust-ima.cfg <<'EOF'
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT ima_policy=tcb ima_template=ima-ng ima_hash=sha256 lockdown=integrity"
EOF
update-grub

install -d -m 0755 /etc/nodetrust
# Kept out of /etc/ima/ so systemd's own loader does not consume the one write.
cat >/etc/nodetrust/ima-policy <<'EOF'
# nodetrust IMA policy (blueprint Section 6.4). Rules match first to last.
# Comments must be on their own lines.
#
# 1. Skip overlayfs (container image files) for every hook.
dont_measure fsmagic=0x794c7630
# 2. Executables, executable mappings, modules, kexec images, firmware and the
#    policy itself, on every other filesystem (tmpfs included).
measure func=BPRM_CHECK mask=MAY_EXEC
measure func=FILE_MMAP mask=MAY_EXEC
measure func=MODULE_CHECK
measure func=KEXEC_KERNEL_CHECK
measure func=KEXEC_INITRAMFS_CHECK
measure func=FIRMWARE_CHECK
measure func=POLICY_CHECK
# 3. Files read by root on ext4 (root filesystem and /boot) and vfat (EFI
#    system partition). Reads on tmpfs and pseudo filesystems are not measured.
measure func=FILE_CHECK mask=^MAY_READ euid=0 fsmagic=0xef53
measure func=FILE_CHECK mask=^MAY_READ euid=0 fsmagic=0x4d44
EOF
chmod 0644 /etc/nodetrust/ima-policy

cat >/usr/local/sbin/nodetrust-load-ima-policy <<'EOF'
#!/bin/sh
# Load the nodetrust IMA policy. The kernel accepts one write per boot.
# Writing the path makes the kernel read (and measure) the file itself; if the
# kernel refuses a path load, fall back to writing the rules directly.
set -eu
POLICY=/etc/nodetrust/ima-policy
TARGET=/sys/kernel/security/ima/policy
if echo "$POLICY" >"$TARGET" 2>/dev/null; then
	echo "nodetrust: IMA policy loaded by path"
	exit 0
fi
grep -v -e '^[[:space:]]*#' -e '^[[:space:]]*$' "$POLICY" >"$TARGET"
echo "nodetrust: IMA policy loaded by content"
EOF
chmod 0755 /usr/local/sbin/nodetrust-load-ima-policy

cat >/etc/systemd/system/nodetrust-ima-policy.service <<'EOF'
[Unit]
Description=Load the nodetrust IMA policy (one write per boot)
DefaultDependencies=no
After=local-fs.target sys-kernel-security.mount
Before=sysinit.target shutdown.target
Conflicts=shutdown.target
ConditionPathExists=/sys/kernel/security/ima/policy

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/nodetrust-load-ima-policy

[Install]
WantedBy=sysinit.target
EOF
systemctl enable nodetrust-ima-policy.service

# --- 6. noexec scratch directories ---------------------------------------------------
add_fstab() { grep -qE "^[^#]*[[:space:]]$2[[:space:]]" /etc/fstab || echo "$1" >>/etc/fstab; }
add_fstab "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,size=2g,mode=1777 0 0" /tmp
add_fstab "tmpfs /dev/shm tmpfs rw,nosuid,nodev,noexec 0 0" /dev/shm
add_fstab "/var/tmp /var/tmp none rw,bind,nosuid,nodev,noexec 0 0" /var/tmp

# --- 7. no SSH, no snap refreshes ------------------------------------------------------
systemctl disable ssh.service ssh.socket || true
systemctl mask ssh.service ssh.socket
rm -f /etc/ssh/ssh_host_*
snap refresh --hold

# --- 7b. nodetrust agent (Phase 3, step 3.3) ------------------------------------------
# A static binary, built and uploaded by build-golden-ami.sh, fetched through a
# short-lived presigned URL and checked against its SHA-256. Because it is in
# the image, the signed manifest covers it and IMA measures it at every start.
curl -fsS --max-time 300 -o /usr/local/bin/nodetrust-agent.new "$AGENT_URL"
echo "$AGENT_SHA256  /usr/local/bin/nodetrust-agent.new" | sha256sum -c --quiet -
install -m 0755 -o root -g root /usr/local/bin/nodetrust-agent.new /usr/local/bin/nodetrust-agent
rm -f /usr/local/bin/nodetrust-agent.new
echo "$VERIFIER_CA_B64" | base64 -d >/etc/nodetrust/verifier-ca.pem
chmod 0644 /etc/nodetrust/verifier-ca.pem
grep -q 'BEGIN CERTIFICATE' /etc/nodetrust/verifier-ca.pem
getent group tss >/dev/null # owner group of /dev/tpmrm0 (tpm-udev)

cat >/etc/systemd/system/nodetrust-agent.service <<'EOF'
[Unit]
Description=nodetrust attestation agent (answers the verifier over mTLS on 9443)
After=network-online.target nodetrust-ima-policy.service
Wants=network-online.target
Before=kubelet.service

[Service]
ExecStart=/usr/local/bin/nodetrust-agent serve
Restart=always
RestartSec=2
# Root for the IMA log (securityfs, mode 0440 root:root) and for IMA to
# measure the canary and the sweep (the policy measures root's reads), the
# tss group for /dev/tpmrm0, and one capability: CAP_SYS_PTRACE, needed to
# read /proc/<pid>/ns/mnt and mountinfo of processes with more capabilities
# than the agent (the mount audit, blueprint 10.3). StateDirectory is the
# only writable place: the canary file.
User=root
SupplementaryGroups=tss
CapabilityBoundingSet=CAP_SYS_PTRACE
AmbientCapabilities=CAP_SYS_PTRACE
NoNewPrivileges=yes
StateDirectory=nodetrust
StateDirectoryMode=0700
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
DevicePolicy=closed
DeviceAllow=/dev/tpmrm0 rw
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
systemctl enable nodetrust-agent.service

# --- 8. build record -------------------------------------------------------------------
cat >/etc/nodetrust/build-info <<EOF
built_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
k8s_minor=${K8S_MINOR}
kubelet=$(dpkg-query -W -f='${Version}' kubelet)
kubeadm=$(dpkg-query -W -f='${Version}' kubeadm)
containerd=$(dpkg-query -W -f='${Version}' containerd)
runc=$(dpkg-query -W -f='${Version}' runc)
kernel_installed=$(dpkg-query -W -f='${Version}' linux-image-aws 2>/dev/null || echo unknown)
kernel=${NEWEST_KERNEL}
agent_sha256=${AGENT_SHA256}
EOF

# --- 9. clean up and power off ---------------------------------------------------------
# The image keeps its original package sources even if the build used the
# fallback archive.
cp -a /root/ubuntu.sources.orig "$SOURCES"
rm -f /root/ubuntu.sources.orig
"${APT[@]}" clean
rm -rf /var/lib/apt/lists/*
cloud-init clean --logs --machine-id
rm -f /etc/udev/rules.d/90-cloud-init-hook-hotplug.rules /var/lib/cloud/hotplug.enabled
journalctl --rotate || true
journalctl --vacuum-time=1s || true
rm -f /root/.bash_history "$0"
sync
marker "NODETRUST_BUILD_RESULT=ok"
systemctl poweroff
