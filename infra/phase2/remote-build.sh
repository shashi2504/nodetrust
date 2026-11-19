#!/usr/bin/env bash
# Runs on the throwaway manifest builder (stock Ubuntu 24.04), as root through
# SSM. build-manifest.sh ships it together with manifest.py.
#
# Usage: remote-build.sh <volume-id> <ami-id> <snapshot-id> <bucket> <region>
#
# Mounts the golden AMI's filesystems read-only from the attached volume,
# builds the manifest twice (determinism check), cross-checks it against the
# image's dpkg md5sums, and uploads it to s3://<bucket>/manifests/<ami-id>/.
set -euo pipefail
VOL="$1" AMI="$2" SNAP="$3" BUCKET="$4" REGION="$5"
cd "$(dirname "$0")"

FAILS=0
pass() { printf 'PASS %-26s %s\n' "$1" "$2"; }
fail() {
	printf 'FAIL %-26s %s\n' "$1" "$2"
	FAILS=$((FAILS + 1))
}
info() { printf 'INFO %-26s %s\n' "$1" "$2"; }

# --- find the attached volume ---------------------------------------------------
# On Nitro, EBS volumes are NVMe devices whose serial is the volume ID
# without the dash.
serial="${VOL/-/}"
dev=""
for _ in $(seq 1 60); do
	dev="$(lsblk -dnpo PATH,SERIAL | awk -v s="$serial" '$2 == s { print $1 }')"
	[ -n "$dev" ] && break
	sleep 2
done
if [ -z "$dev" ]; then
	fail volume-device "no block device with serial $serial"
	exit 1
fi
pass volume-device "$VOL is $dev"
udevadm settle

declare -A P_TYPE P_LABEL P_UUID
parts=()
while read -r p t; do
	[ "$t" = part ] || continue
	parts+=("$p")
	P_TYPE[$p]="$(blkid -o value -s TYPE "$p" || true)"
	P_LABEL[$p]="$(blkid -o value -s LABEL "$p" || true)"
	P_UUID[$p]="$(blkid -o value -s UUID "$p" || true)"
done < <(lsblk -lnpo PATH,TYPE "$dev")

ro_opts() { # ext4: skip journal replay so nothing is written to the volume
	case "$1" in ext4 | ext3) echo ro,noload ;; *) echo ro ;; esac
}

# --- mount / ------------------------------------------------------------------------
rootp=""
for p in "${parts[@]}"; do
	if [ "${P_LABEL[$p]}" = cloudimg-rootfs ]; then rootp="$p"; fi
done
if [ -z "$rootp" ]; then
	fail mount-root "no partition labelled cloudimg-rootfs on $dev"
	exit 1
fi
install -d /mnt/nt/root
mount -o "$(ro_opts "${P_TYPE[$rootp]}")" "$rootp" /mnt/nt/root
pass mount-root "$rootp (${P_TYPE[$rootp]}) read-only"
MOUNTS=(--mount "/=/mnt/nt/root")

# --- mount /boot and /boot/efi as the image's own fstab says ------------------------
find_part() { # find_part LABEL=x | UUID=y -> partition on the attached disk
	local spec="$1" p
	for p in "${parts[@]}"; do
		case "$spec" in
		LABEL=*) [ "${P_LABEL[$p]}" = "${spec#LABEL=}" ] && echo "$p" && return ;;
		UUID=*) [ "${P_UUID[$p]}" = "${spec#UUID=}" ] && echo "$p" && return ;;
		esac
	done
	return 0
}

for mp in /boot /boot/efi; do
	spec="$(awk -v mp="$mp" '$1 !~ /^#/ && $2 == mp { print $1; exit }' /mnt/nt/root/etc/fstab)"
	if [ -z "$spec" ]; then
		info "fstab$mp" "no separate filesystem; contents are on /"
		continue
	fi
	p="$(find_part "$spec")"
	if [ -z "$p" ]; then
		fail "mount$mp" "fstab has $spec but no such partition on $dev"
		continue
	fi
	dir=/mnt/nt/boot
	[ "$mp" = /boot/efi ] && dir=/mnt/nt/efi
	install -d "$dir"
	mount -o "$(ro_opts "${P_TYPE[$p]}")" "$p" "$dir"
	suffix=""
	[ "${P_TYPE[$p]}" = vfat ] && suffix=":nonposix"
	MOUNTS+=(--mount "$mp=$dir$suffix")
	pass "mount$mp" "$p (${P_TYPE[$p]}, $spec) read-only"
done

# --- snaps ---------------------------------------------------------------------------
# Snaps run from squashfs images mounted at /snap/<name>/<revision>, so their
# files (the SSM agent among them) are not on any of the partitions above.
# Mount each image read-only and add it to the manifest at that path.
SNAPS=()
for img in /mnt/nt/root/var/lib/snapd/snaps/*.snap; do
	[ -e "$img" ] || continue
	base="$(basename "$img" .snap)"
	name="${base%_*}" rev="${base##*_}"
	dir="/mnt/nt/snap/$base"
	install -d "$dir"
	if mount -t squashfs -o ro,loop "$img" "$dir"; then
		MOUNTS+=(--mount "/snap/$name/$rev=$dir")
		SNAPS+=("$name/$rev")
	else
		fail "mount-snap" "could not mount $base.snap"
	fi
done
if [ "${#SNAPS[@]}" -gt 0 ]; then
	pass mount-snaps "${#SNAPS[@]} snaps read-only: ${SNAPS[*]}"
else
	info mount-snaps "no snaps in the image"
fi

if [ "$FAILS" -ne 0 ]; then exit 1; fi

# --- build twice ---------------------------------------------------------------------
META=(--meta "ami_id=$AMI" --meta "snapshot_id=$SNAP" --meta "region=$REGION")
start=$SECONDS
out1="$(python3 manifest.py build "${MOUNTS[@]}" "${META[@]}" -o manifest.json)"
info build-1 "$out1 ($((SECONDS - start)) s)"
start=$SECONDS
python3 manifest.py build "${MOUNTS[@]}" "${META[@]}" -o manifest-2.json >/dev/null
info build-2 "$((SECONDS - start)) s"
d1="$(python3 manifest.py digest --quiet manifest.json)"
d2="$(python3 manifest.py digest --quiet manifest-2.json)"
if [ "$d1" = "$d2" ] && [ "${out1##*entries_sha256=}" = "$d1" ]; then
	pass deterministic "two builds give entries_sha256 $d1"
else
	fail deterministic "build 1 $d1, build 2 $d2"
fi
rm -f manifest-2.json

shadow="$(python3 -c 'import json,sys; m=json.load(open("manifest.json")); print(m["stats"]["shadowed"], " ".join(m["shadowed"][:5]))')"
if [ "${shadow%% *}" = 0 ]; then
	pass no-shadowed "no root-fs files hidden under /boot or /boot/efi"
else
	fail no-shadowed "$shadow"
fi

# --- files the later phases depend on ------------------------------------------------
want() { # want <name> <glob>
	local hit
	if hit="$(python3 manifest.py find manifest.json "$2")"; then
		hit="${hit%%$'\n'*}"
		pass "file:$1" "${hit:0:16}... ${hit#*  }"
	else
		fail "file:$1" "nothing matches $2"
	fi
}
want kubelet /usr/bin/kubelet
want kubeadm /usr/bin/kubeadm
want containerd /usr/bin/containerd
want runc '/usr/*bin/runc'
want kernel '/boot/vmlinuz-*'
want initrd '/boot/initrd.img-*'
want grub-cfg '/boot/grub/grub.cfg'
want shim '/boot/efi/EFI/BOOT/BOOTX64.EFI'
want ima-policy /etc/nodetrust/ima-policy
want build-info /etc/nodetrust/build-info
want modules-lock /usr/local/sbin/nodetrust-lock-modules
want ssm-agent '/snap/amazon-ssm-agent/*/amazon-ssm-agent'

if python3 -c 'import json,sys; sys.exit(0 if json.load(open("manifest.json"))["build_info"] else 1)'; then
	pass build-info-parsed "$(python3 -c 'import json; b=json.load(open("manifest.json"))["build_info"]; print(" ".join(f"{k}={v}" for k,v in b.items()))' | cut -c1-200)"
else
	fail build-info-parsed "manifest build_info is empty"
fi

# --- independent check against dpkg ------------------------------------------------
# A second read of every packaged file: its md5 must match what dpkg recorded
# at install time, and its SHA-256 must match the manifest.
start=$SECONDS
if dp="$(python3 manifest.py check-dpkg manifest.json "${MOUNTS[@]}")"; then
	pass dpkg-crosscheck "$(head -1 <<<"$dp") ($((SECONDS - start)) s)"
else
	fail dpkg-crosscheck "$(head -1 <<<"$dp")"
	tail -n +2 <<<"$dp"
fi

for d in /mnt/nt/snap/*/; do umount "$d" 2>/dev/null || true; done
umount /mnt/nt/efi 2>/dev/null || true
umount /mnt/nt/boot 2>/dev/null || true
umount /mnt/nt/root

if [ "$FAILS" -ne 0 ]; then
	echo "SUMMARY fails=$FAILS (manifest not uploaded)"
	exit 1
fi

# --- upload --------------------------------------------------------------------------
# gzip -n leaves out the name and time, so the same manifest always gives the
# same .gz bytes.
gzip -9nf manifest.json
info manifest-gz-sha256 "$(sha256sum manifest.json.gz | cut -d' ' -f1)"
info manifest-gz-bytes "$(stat -c %s manifest.json.gz)"
# Stock Ubuntu has no AWS CLI; the snap is the quickest way to get one.
AWS="$(command -v aws || true)"
if [ -z "$AWS" ]; then
	snap wait system seed.loaded
	snap install aws-cli --classic >/dev/null
	AWS=/snap/bin/aws
fi
key="manifests/$AMI/manifest.json.gz"
if "$AWS" s3 cp --region "$REGION" --only-show-errors manifest.json.gz "s3://$BUCKET/$key"; then
	pass upload "s3://$BUCKET/$key"
else
	fail upload "s3://$BUCKET/$key"
fi
echo "SUMMARY fails=$FAILS"
[ "$FAILS" -eq 0 ]
