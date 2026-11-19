#!/bin/bash
# Diagnostics run on the control plane by diagnose.sh: why Calico or pods are
# not ready. Read-only.
export KUBECONFIG=/etc/kubernetes/admin.conf
echo "### nodes"
kubectl get nodes -o wide --no-headers
kubectl get nodes -o custom-columns='NAME:.metadata.name,TAINTS:.spec.taints[*].key' --no-headers
echo "### pods not Running"
kubectl get pods -A -o wide --no-headers | grep -v -E ' (Running|Completed) ' || echo "(none)"
echo "### calico-system pods"
kubectl -n calico-system get pods -o wide --no-headers
for p in $(kubectl -n calico-system get pods -l k8s-app=calico-node -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.containerStatuses[0].ready}{"\n"}{end}' | awk '$2 != "true" {print $1}'); do
	echo "### not ready: $p"
	kubectl -n calico-system get pod "$p" -o jsonpath='{.spec.nodeName}{"\n"}'
	kubectl -n calico-system describe pod "$p" | sed -n '/^Events:/,$p' | tail -12
	echo "--- calico-node log (errors and warnings)"
	kubectl -n calico-system logs "$p" -c calico-node --tail=400 2>&1 |
		grep -iE 'error|fail|warn|module|ipset|iptables|nft|not supported|readiness' | tail -40
done
echo "### recent warning events"
kubectl get events -A --field-selector type=Warning --sort-by=.lastTimestamp 2>/dev/null | tail -15
