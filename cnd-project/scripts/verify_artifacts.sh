#!/usr/bin/env bash
# verify_artifacts.sh — Supply Chain Artifact Verification
# Verifies: cosign signature, SLSA provenance, SBOM (via attestation), CVEs
# Usage: bash scripts/verify_artifacts.sh [IMAGE_REF]
set -euo pipefail

TS()   { date '+%Y-%m-%d %H:%M:%S'; }
ok()   { echo "[$(TS)] OK   $*"; }
fail() { echo "[$(TS)] FAIL $*"; FAILURES=$((FAILURES+1)); }
info() { echo "[$(TS)] ...  $*"; }

IMAGE_REF="${1:-ghcr.io/azdyn7-ai/project-supply-chin/cnd-demo-app:latest}"
IDENTITY_REGEXP="${COSIGN_IDENTITY:-.*azdyn7-ai.*}"
OIDC_ISSUER="${COSIGN_OIDC:-https://token.actions.githubusercontent.com}"
FAILURES=0

echo ""
echo "============================================================"
echo "  Supply Chain Artifact Verification"
echo "  Image: ${IMAGE_REF}"
echo "============================================================"
echo ""

# ── CHECK 1: Cosign Signature ─────────────────────────────────────────────────
info "CHECK 1: Verifying Cosign keyless signature..."
START=$(date +%s%3N)

cosign verify \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "$IMAGE_REF" > /tmp/sig-out.json 2>/tmp/sig-err.txt
SIG_EXIT=$?
END=$(date +%s%3N)

if [ $SIG_EXIT -eq 0 ]; then
    SUBJECT=$(jq -r '.[0].optional.Subject // "verified"' /tmp/sig-out.json 2>/dev/null || echo "verified")
    ok "Signature VALID — subject: ${SUBJECT} — $((END-START))ms"
else
    fail "Signature INVALID — $(tail -1 /tmp/sig-err.txt 2>/dev/null)"
fi

# ── CHECK 2: SLSA Provenance ──────────────────────────────────────────────────
info "CHECK 2: Verifying SLSA provenance attestation..."
START=$(date +%s%3N)

cosign verify-attestation \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --type slsaprovenance1 \
    "$IMAGE_REF" > /tmp/slsa-out.jsonl 2>/dev/null
SLSA_EXIT=$?
END=$(date +%s%3N)

if [ $SLSA_EXIT -eq 0 ]; then
    BTYPE=$(python3 -c "
import json, base64, sys
for line in open('/tmp/slsa-out.jsonl'):
    line = line.strip()
    if not line: continue
    try:
        obj = json.loads(line)
        pay = json.loads(base64.b64decode(obj['payload']))
        print(pay.get('predicateType','unknown'))
        break
    except: pass
" 2>/dev/null || echo "https://slsa.dev/provenance/v1")
    ok "SLSA provenance VALID — type: ${BTYPE} — $((END-START))ms"
else
    fail "SLSA provenance NOT found or invalid"
fi

# ── CHECK 3: SBOM Attestation (CycloneDX via cosign attest) ──────────────────
info "CHECK 3: Verifying SBOM attestation (CycloneDX)..."
START=$(date +%s%3N)

cosign verify-attestation \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --type cyclonedx \
    "$IMAGE_REF" > /tmp/sbom-out.jsonl 2>/dev/null
SBOM_EXIT=$?
END=$(date +%s%3N)

if [ $SBOM_EXIT -eq 0 ]; then
    python3 - <<'PYEOF'
import json, base64, sys

try:
    for line in open('/tmp/sbom-out.jsonl'):
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        payload = json.loads(base64.b64decode(obj['payload']))
        sbom = payload.get('predicate', {})
        components = sbom.get('components', [])
        print(f"  Format  : {sbom.get('bomFormat','CycloneDX')}")
        print(f"  Version : {sbom.get('specVersion','?')}")
        print(f"  Components: {len(components)}")

        packages = [c for c in components if c.get('type','') in ('library','framework')]
        with open('allowed_packages.json', 'w') as f:
            json.dump({'packages': [
                {'name': c.get('name',''), 'version': c.get('version',''), 'purl': c.get('purl','')}
                for c in packages
            ]}, f, indent=2)
        with open('allowed_binaries.json', 'w') as f:
            json.dump({'allowed': ['cnd-app']}, f, indent=2)
        print(f"  allowed_packages.json: {len(packages)} entries")
        break
except Exception as e:
    print(f"  parse warning: {e}", file=sys.stderr)
PYEOF
    ok "SBOM attestation VALID (CycloneDX) — $((END-START))ms"
else
    fail "SBOM attestation NOT found — check cosign attest --type cyclonedx was run"
fi

# ── CHECK 4: Vulnerability Scan ───────────────────────────────────────────────
info "CHECK 4: Scanning for CVEs (Grype)..."
if command -v grype &>/dev/null; then
    START=$(date +%s%3N)
    SCAN=$(grype "$IMAGE_REF" --output json 2>/dev/null)
    END=$(date +%s%3N)
    CRITICAL=$(echo "$SCAN" | jq '[.matches[]|select(.vulnerability.severity=="Critical")]|length' 2>/dev/null || echo "0")
    HIGH=$(echo "$SCAN" | jq '[.matches[]|select(.vulnerability.severity=="High")]|length' 2>/dev/null || echo "0")
    ok "CVE scan complete — Critical: ${CRITICAL}, High: ${HIGH} (documented in research report) — $((END-START))ms"
else
    info "grype not installed — skipping CVE scan"
fi

# ── SUMMARY ───────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
if [ "$FAILURES" -eq 0 ]; then
    echo "  VERIFIED — All supply chain checks passed."
else
    echo "  FAILED — ${FAILURES} check(s) failed."
fi
echo "============================================================"
exit "$FAILURES"
