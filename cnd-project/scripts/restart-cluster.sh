#!/usr/bin/env bash
# restart-cluster.sh — CND Cluster Recovery after VM reboot
# Usage: cd ~/Project-Supply-Chin/cnd-project && bash scripts/restart-cluster.sh
set -euo pipefail

TS()   { date '+%Y-%m-%d %H:%M:%S'; }
ok()   { echo "[$(TS)] OK  $*"; }
info() { echo "[$(TS)] ... $*"; }

echo ""
echo "============================================================"
echo "  CND Cluster Startup"
echo "============================================================"
echo ""

# 1. Minikube
if ! minikube status -p cnd-cluster 2>/dev/null | grep -q "Running"; then
    info "Starting Minikube cluster..."
    minikube start -p cnd-cluster
    ok "Minikube started"
else
    ok "Minikube already running"
fi

kubectl config use-context cnd-cluster
ok "kubectl context = cnd-cluster"

# 2. Kyverno — restart pods so policies apply cleanly
info "Restarting Kyverno admission controller..."
kubectl delete pods -n kyverno --all --ignore-not-found=true
kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/part-of=kyverno \
    -n kyverno --timeout=120s 2>/dev/null \
    && ok "Kyverno ready" || info "Kyverno pods still starting — continue"

# 3. Apply updated Kyverno policies
kubectl apply -f kubernetes/kyverno/ > /dev/null 2>&1
ok "Kyverno policies applied"

# 4. Falco
kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/name=falco \
    -n falco --timeout=60s 2>/dev/null \
    && ok "Falco ready" || info "Falco not ready yet"

# 5. Tetragon
kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/name=tetragon \
    -n kube-system --timeout=60s 2>/dev/null \
    && ok "Tetragon ready" || info "Tetragon not ready yet"

# 6. cnd-demo-app
kubectl wait --for=condition=ready pod \
    -l app=cnd-demo-app \
    -n cnd-demo --timeout=60s 2>/dev/null \
    && ok "cnd-demo-app ready" || info "cnd-demo-app not ready yet"

# 7. Prometheus port-forward (background)
if ! pgrep -f "port-forward.*9090" > /dev/null 2>&1; then
    kubectl port-forward svc/prometheus-kube-prometheus-prometheus \
        9090:9090 -n monitoring > /dev/null 2>&1 &
    sleep 2
    ok "Prometheus port-forward: localhost:9090"
fi

# 8. Results directory
mkdir -p evaluation/results
ok "evaluation/results ready"

echo ""
echo "============================================================"
echo "  Cluster ready. Run verification scripts:"
echo ""
echo "  bash scripts/verify_artifacts.sh"
echo "  bash scripts/test_admission.sh"
echo "  bash scripts/simulate_attacks.sh"
echo "============================================================"
echo ""
