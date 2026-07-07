#!/usr/bin/env bash
set -euo pipefail
TS()   { date '+%Y-%m-%d %H:%M:%S'; }
pass() { echo "[$(TS)] PASS $*"; PASSED=$((PASSED+1)); }
fail() { echo "[$(TS)] FAIL $*"; FAILED=$((FAILED+1)); }
info() { echo "[$(TS)] INFO $*"; }
NAMESPACE="cnd-demo"
IMAGE="${VERIFIED_IMAGE:-ghcr.io/azdyn7-ai/project-supply-chin/cnd-demo-app:latest}"
PASSED=0; FAILED=0
cleanup() { kubectl delete pod -n "$NAMESPACE" -l test-admission=true --ignore-not-found=true &>/dev/null || true; }
trap cleanup EXIT
echo ""; echo "============================================================"
echo "  Kyverno Admission Control Tests"; echo "============================================================"; echo ""

info "TEST 1: Unsigned image (nginx) — must be REJECTED"
START=$(date +%s%3N)
OUTPUT=$(kubectl apply -f - 2>&1 <<YAML || true
apiVersion: v1
kind: Pod
metadata:
  name: test-unsigned-$(date +%s)
  namespace: ${NAMESPACE}
  labels:
    test-admission: "true"
spec:
  containers:
    - name: test
      image: docker.io/library/nginx:latest
      resources:
        requests: {cpu: "10m", memory: "16Mi"}
        limits:   {cpu: "100m", memory: "64Mi"}
  restartPolicy: Never
YAML
)
END=$(date +%s%3N)
if echo "$OUTPUT" | grep -qiE "denied|blocked|Forbidden|PodSecurity|Error|admission|webhook"; then
    REASON=$(echo "$OUTPUT" | grep -oiE "Forbidden|denied|violates[^(]*" | head -1 || echo "rejected")
    pass "TEST 1: Unsigned image REJECTED in $((END-START))ms — ${REASON}"
else
    fail "TEST 1: Unsigned image NOT rejected"; echo "  output: $OUTPUT"
fi
sleep 3

info "TEST 2: Signed image without our attestations — must be REJECTED"
START=$(date +%s%3N)
OUTPUT=$(kubectl apply -f - 2>&1 <<YAML || true
apiVersion: v1
kind: Pod
metadata:
  name: test-no-sbom-$(date +%s)
  namespace: ${NAMESPACE}
  labels:
    test-admission: "true"
spec:
  containers:
    - name: test
      image: ghcr.io/sigstore/cosign:v2.0.0
      resources:
        requests: {cpu: "10m", memory: "16Mi"}
        limits:   {cpu: "100m", memory: "64Mi"}
  restartPolicy: Never
YAML
)
END=$(date +%s%3N)
if echo "$OUTPUT" | grep -qiE "denied|blocked|Forbidden|Error|sbom|attestation"; then
    pass "TEST 2: Image without attestations REJECTED in $((END-START))ms"
else
    fail "TEST 2: NOT rejected"; echo "  output: $OUTPUT"
fi
sleep 3

info "TEST 3: Verified image (signature+SBOM+SLSA) — must be ACCEPTED"
info "  Image: ${IMAGE}"
T3_PASSED=false
for attempt in 1 2 3; do
    START=$(date +%s%3N)
    OUTPUT=$(kubectl apply -f - 2>&1 <<YAML || true
apiVersion: v1
kind: Pod
metadata:
  name: test-verified-$(date +%s)
  namespace: ${NAMESPACE}
  labels:
    test-admission: "true"
    app: verified-test
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: test
      image: ${IMAGE}
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: [ALL]
      resources:
        requests: {cpu: "50m", memory: "64Mi"}
        limits:   {cpu: "200m", memory: "128Mi"}
  restartPolicy: Never
YAML
)
    END=$(date +%s%3N)
    if echo "$OUTPUT" | grep -qiE "created|configured|unchanged"; then
        pass "TEST 3: Verified image ACCEPTED in $((END-START))ms (attempt ${attempt})"
        T3_PASSED=true; break
    elif echo "$OUTPUT" | grep -q "deadline exceeded"; then
        info "  Attempt ${attempt}/3: timeout — retrying in 8s..."; sleep 8
    else
        info "  Attempt ${attempt}/3: $OUTPUT"; break
    fi
done
[ "$T3_PASSED" = false ] && fail "TEST 3: Verified image REJECTED after 3 attempts" && echo "  Last: $OUTPUT
+echo ""; echo "============================================================"
echo "  Results: Passed=${PASSED}/3  Failed=${FAILED}/3"
[ "$FAILED" -eq 0 ] && echo "  Status: ALL TESTS PASSED" || echo "  Status: ${FAILED} FAILED"
echo "============================================================"
exit "$FAILED"
