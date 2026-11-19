#!/bin/bash
# In-cluster checks for step 1.3, run as root on the control plane through
# SSM by check-cluster.sh. Usage: remote-check.sh <expected-worker-count>
set -uo pipefail
export KUBECONFIG=/etc/kubernetes/admin.conf
WANT_WORKERS="${1:?expected worker count}"
NS=nodetrust-gate
IMG=public.ecr.aws/docker/library/busybox:1.36
TAINT=trust.k8s-attest.io/unattested
pass=0
fail=0
result() {
	printf '%-4s %-26s %s\n' "$1" "$2" "$3"
	case "$1" in PASS) pass=$((pass + 1)) ;; FAIL) fail=$((fail + 1)) ;; esac
}

# A fresh control plane needs several minutes (kubeadm init, then the Calico
# operator creating its CRDs). Wait up to 20 minutes, but stop early if
# cloud-init reports that the bootstrap script failed.
for _ in $(seq 1 120); do
	[ -f /var/lib/nodetrust-bootstrap-done ] && break
	if cloud-init status 2>/dev/null | grep -q 'status: error'; then
		break
	fi
	sleep 10
done
if [ ! -f /var/lib/nodetrust-bootstrap-done ]; then
	result FAIL cp-bootstrap "bootstrap did not finish ($(cloud-init status 2>/dev/null | tr '\n' ' ')). Last log lines:"
	tail -n 25 /var/log/nodetrust-bootstrap.log 2>/dev/null | sed 's/^/    /'
	echo "SUMMARY pass=$pass fail=$fail"
	exit 1
fi
result PASS cp-bootstrap "kubeadm init and Calico install finished"

# Nodes: control plane + workers, all Ready (wait up to 15 minutes).
want=$((WANT_WORKERS + 1))
for _ in $(seq 1 90); do
	ready="$(kubectl get nodes --no-headers 2>/dev/null | awk '$2 == "Ready"' | wc -l)"
	[ "$ready" -ge "$want" ] && break
	sleep 10
done
if [ "$ready" -ge "$want" ]; then
	result PASS nodes-ready "$ready of $want nodes Ready"
else
	result FAIL nodes-ready "$ready of $want nodes Ready: $(kubectl get nodes --no-headers 2>&1 | tr '\n' ';')"
fi
result INFO kubernetes "$(kubectl version -o json 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["serverVersion"]["gitVersion"])' 2>/dev/null)"

# Workers: unattested taint and an AWS providerID (blueprint 6.1, 10.4).
workers="$(kubectl get nodes -l '!node-role.kubernetes.io/control-plane' -o name)"
n=0
for node in $workers; do
	n=$((n + 1))
	name="${node#node/}"
	if kubectl get "$node" -o jsonpath='{.spec.taints[*].key}' | grep -qw "$TAINT"; then
		result PASS "taint:$name" "$TAINT present"
	else
		result FAIL "taint:$name" "$TAINT missing"
	fi
	pid="$(kubectl get "$node" -o jsonpath='{.spec.providerID}')"
	if [[ "$pid" =~ ^aws:///[a-z0-9-]+/i-[0-9a-f]+$ ]]; then
		result PASS "provider-id:$name" "$pid"
	else
		result FAIL "provider-id:$name" "unexpected providerID '$pid'"
	fi
done
[ "$n" -eq "$WANT_WORKERS" ] || result FAIL worker-count "found $n workers, expected $WANT_WORKERS"

# Calico.
# The operator can publish its status a little after the pods are up, so poll
# for up to 5 minutes, and on failure print what it actually reports.
avail=""
for _ in $(seq 1 30); do
	avail="$(kubectl get tigerastatus calico -o jsonpath='{.status.conditions[?(@.type=="Available")].status}' 2>/dev/null)"
	[ "$avail" = True ] && break
	sleep 10
done
if [ "$avail" = True ]; then
	result PASS calico-available "tigerastatus calico Available"
else
	result FAIL calico-available "Available=${avail:-empty}; tigerastatus: $(kubectl get tigerastatus --no-headers 2>&1 | tr -s ' ' | tr '\n' ';')"
fi
result INFO calico-version "$(kubectl get clusterinformation default -o jsonpath='{.spec.calicoVersion}' 2>/dev/null || echo unknown)"
dp="$(kubectl get installation default -o jsonpath='{.spec.calicoNetwork.linuxDataplane}' 2>/dev/null)"
if [ "$dp" = Iptables ]; then
	result PASS calico-dataplane "iptables dataplane (pod traffic passes host netfilter)"
else
	result FAIL calico-dataplane "dataplane is '${dp:-unknown}', expected Iptables"
fi

# Workload test: two pods on different workers, cross-node HTTP and DNS.
kubectl delete namespace "$NS" --ignore-not-found --wait=true >/dev/null 2>&1
kubectl create namespace "$NS" >/dev/null
cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: $NS
spec:
  replicas: 2
  selector:
    matchLabels: {app: echo}
  template:
    metadata:
      labels: {app: echo}
    spec:
      tolerations:
      - {key: $TAINT, operator: Exists, effect: NoSchedule}
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchLabels: {app: echo}
            topologyKey: kubernetes.io/hostname
      containers:
      - name: echo
        image: $IMG
        command: ["sh", "-c", "echo nodetrust > /tmp/index.html && httpd -f -p 8080 -h /tmp"]
EOF
if kubectl -n "$NS" rollout status deploy/echo --timeout=300s >/dev/null 2>&1; then
	result PASS test-pods "2 pods running on 2 different workers"
	mapfile -t pods < <(kubectl -n "$NS" get pods -l app=echo -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')
	ipb="$(kubectl -n "$NS" get pod "${pods[1]}" -o jsonpath='{.status.podIP}')"
	if kubectl -n "$NS" exec "${pods[0]}" -- wget -qO- -T 5 "http://$ipb:8080/index.html" 2>/dev/null | grep -q nodetrust; then
		result PASS pod-to-pod "cross-node pod traffic works (Calico VXLAN)"
	else
		result FAIL pod-to-pod "pod ${pods[0]} cannot reach $ipb:8080"
	fi
	if kubectl -n "$NS" exec "${pods[0]}" -- nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
		result PASS cluster-dns "kubernetes.default resolves from a pod"
	else
		result FAIL cluster-dns "DNS lookup from a pod failed"
	fi

	# NetworkPolicy: deny all ingress, expect the request to fail, then allow it
	# again. With kernel module loading locked, this shows Calico's policy
	# dataplane has every module it needs.
	cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
  namespace: $NS
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF
	blocked=false
	for _ in $(seq 1 12); do
		if ! kubectl -n "$NS" exec "${pods[0]}" -- wget -qO- -T 3 "http://$ipb:8080/index.html" >/dev/null 2>&1; then
			blocked=true
			break
		fi
		sleep 5
	done
	kubectl -n "$NS" delete networkpolicy deny-all-ingress >/dev/null 2>&1
	allowed=false
	for _ in $(seq 1 12); do
		if kubectl -n "$NS" exec "${pods[0]}" -- wget -qO- -T 3 "http://$ipb:8080/index.html" 2>/dev/null | grep -q nodetrust; then
			allowed=true
			break
		fi
		sleep 5
	done
	if $blocked && $allowed; then
		result PASS network-policy "deny-all blocked pod traffic; removing it restored it"
	else
		result FAIL network-policy "blocked=$blocked restored=$allowed"
	fi
else
	result FAIL test-pods "test pods did not become ready: $(kubectl -n "$NS" get pods --no-headers 2>&1 | tr '\n' ';')"
fi
kubectl delete namespace "$NS" --wait=false >/dev/null 2>&1

echo "SUMMARY pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
