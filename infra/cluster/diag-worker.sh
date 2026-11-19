#!/bin/bash
# Diagnostics run on a worker by diagnose.sh: is the module lock blocking
# something Calico or kube-proxy needs? Read-only.
echo "### $(hostname)  modules_disabled=$(sysctl -n kernel.modules_disabled)"
echo "### lock and preload units"
systemctl is-active systemd-modules-load.service nodetrust-modules-lock.service
journalctl -b -u nodetrust-modules-lock.service -o cat --no-pager | tail -3
echo "### kernel messages about modules, ipset, netfilter"
dmesg 2>/dev/null | grep -iE 'module|request_module|ip_set|ipset|nf_tables|xt_|x_tables|vxlan' | tail -25
echo "### ipset types the kernel offers"
ipset --version 2>/dev/null || echo "(no host ipset tool)"
find "/lib/modules/$(uname -r)/kernel/net/netfilter/ipset/" -name "*.ko*" -printf "%f\n" 2>/dev/null | sed "s/\.ko.*//" | sort | tr "\n" " "
echo
echo "### loaded ip_set and xt modules"
lsmod | awk 'NR>1 {print $1}' | grep -E '^(ip_set|xt_|nft_|nf_)' | tr '\n' ' '
echo
echo "### kubelet errors (last 30 min)"
journalctl -u kubelet --since -30min -o cat --no-pager 2>/dev/null | grep -iE 'error|fail' | tail -10
