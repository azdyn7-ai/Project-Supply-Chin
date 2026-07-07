# CND Project — Integrated Supply Chain Security Framework

**Strengthening Cloud Software Supply Chain Security through the Integration of SLSA, Sigstore, and SBOM with Continuous Runtime Verification**

> Bachelor's Graduation Project | Department of Computer Network Engineering and Distributed Systems  
> Faculty of Engineering and Information Technology, Taiz University, Yemen  
> University: https://www.taiz.edu.ye/  
> Students: Ezzaldeen Sultan Ahmed and Tawhib AbdlQAder Hassan

---

## Project Overview

This repository presents a comprehensive DevSecOps-oriented research and implementation framework for strengthening software supply chain security in cloud-native environments. The project addresses a critical gap in modern containerized systems: the separation between build-time assurance and runtime protection. By combining cryptographic image verification, software bill of materials (SBOM) validation, SLSA provenance attestation, admission control, and runtime monitoring, the system offers a layered defense model for securing container deployments from image tampering, malicious dependency injection, and post-deployment compromise.

The work was developed as a Bachelor's graduation project and is intended to demonstrate how academic research principles can be translated into a practical, production-relevant security architecture. The implementation is designed not only as a technical prototype, but also as a reproducible framework for evaluation, demonstration, and future extension in both academic and professional environments.

## Academic and Research Significance

The core innovation of this project is the integration of build-time verification and runtime detection through a provenance-enrichment mechanism. Rather than treating security as a single-point control, the architecture creates a continuous chain of trust that links:

- image integrity at build time,
- admission-time policy enforcement,
- runtime behavioral detection, and
- feedback-driven remediation.

This multi-layered strategy provides a stronger security posture for organizations adopting Kubernetes-based workloads and modern CI/CD pipelines.

## Construction and Implementation Process

The implementation follows a structured pipeline that can be summarized in four phases:

1. Build-time verification: Docker images are built, signed with Cosign, scanned with Grype, and accompanied by SBOM and SLSA provenance metadata.
2. Admission-time enforcement: Kyverno policies verify image signatures, SBOM compliance, and provenance attestation before deployment is allowed.
3. Runtime monitoring: Falco and Tetragon observe container behavior and detect suspicious process execution, package-manager activity, sensitive file access, and unauthorized network behavior.
4. Feedback and reporting: the feedback service collects evidence, enriches incidents with provenance context, and produces results suitable for evaluation and presentation.

## Tools and Technologies Used

The project integrates a modern DevSecOps toolchain, including:

- GitHub Actions for CI/CD automation and artifact generation
- Docker and Buildx for container image construction
- Cosign for keyless image signing and verification
- Syft for SBOM generation
- Grype for vulnerability scanning
- SLSA provenance attestation for build integrity evidence
- Kyverno for Kubernetes admission control
- Falco for runtime threat detection
- Tetragon for eBPF-based process and syscall tracing
- Prometheus and Grafana for monitoring and metrics visualization
- Go, Python, and Bash for the implementation of services and automation scripts

## Evaluation, Results, and Demonstration

The repository includes an end-to-end evaluation workflow that validates the framework under realistic attack scenarios. The automated workflow supports:

- admission-control testing for unsigned or tampered images,
- runtime attack simulation for shell execution and malicious dependency behavior,
- false-positive analysis for clean deployments, and
- performance and overhead measurement for the security pipeline.

The resulting outputs are stored in the evaluation directory and include CSV reports, analysis scripts, and chart-generation support for academic presentation and documentation.

## Future Management and Project Evolution

The project is designed to be extensible and maintainable. Future management should focus on the following areas:

- operational hardening for production deployment environments,
- expansion of detection rules and policy coverage,
- integration with additional registries and artifact repositories,
- stronger evidence correlation between build-time and runtime telemetry,
- incorporation of policy-as-code and continuous compliance workflows,
- broader benchmarking and comparison with other supply-chain security frameworks.

This roadmap ensures that the project remains relevant as both an academic contribution and a practical reference architecture for secure cloud-native software delivery.

---

## Project Structure

```
cnd-project/
├── app/                          # Go microservice (gin + logrus + uuid)
│   ├── main.go                  # /health, /version, /api/data endpoints
│   ├── go.mod / go.sum
│   └── Dockerfile               # Multi-stage, distroless runtime
│
├── enrichment-service/          # ★ CORE INNOVATION — Provenance Bridge
│   ├── main.py                  # Pod watcher + SBOM parser + Falco rule generator
│   ├── Dockerfile
│   ├── requirements.txt
│   └── k8s/deployment.yaml      # Deployment + RBAC + Service
│
├── feedback-service/            # Runtime → Build feedback loop
│   ├── main.py                  # Falco webhook receiver + remediation suggester
│   ├── Dockerfile
│   └── k8s/deployment.yaml
│
├── .github/workflows/           # ← at the repository root (one level above cnd-project/)
│   ├── build-sign-sbom.yml      # CI/CD: Build → Sign → SBOM → SLSA → Scan
│   └── verify-and-deploy.yml    # Supply chain verification gate
│
├── kubernetes/
│   ├── base/                    # Namespace + Deployment + ServiceAccount
│   ├── kyverno/                 # 3 ClusterPolicies (signature + SBOM + SLSA)
│   ├── falco/                   # SBOM-enriched custom rules + Helm values
│   ├── tetragon/                # TracingPolicy (eBPF LSM enforcement)
│   └── monitoring/              # Prometheus + Grafana
│
├── scripts/
│   ├── validate_env.sh          # Environment validation (run first!)
│   ├── setup-cluster.sh         # Full cluster setup (Minikube + all tools)
│   ├── build_pipeline.sh        # SLSA L3 build: build+sign+SBOM+provenance
│   ├── verify_artifacts.sh      # Verify: signature + SLSA + SBOM
│   ├── test_admission.sh        # 3 Kyverno admission tests (PASS/FAIL)
│   ├── simulate_attacks.sh      # 3 scenarios × 5 runs → detection_results.csv
│   ├── collect_metrics.sh       # 3-mode overhead comparison → CSV
│   └── watch-falco.sh           # Live Falco alert monitor
│
└── evaluation/
    ├── analyze_results.py       # Stats + charts + t-test + LaTeX table
    └── results/                 # CSV and JSON outputs
```

---

## Quick Start

### Option A — Quick demo (local machine, no cluster)

The demo microservice exposes `/health`, `/version` and `/api/data`. A lightweight local runtime is included for rapid evaluation and demonstration without requiring a Kubernetes cluster.

```bash
python cnd-project/app/main.py      # Flask demo  → http://localhost:5000
# …or the Go service:
cd cnd-project/app && go run .       # → http://localhost:8080
```

### Option B — Full framework (Ubuntu 22.04 LTS, kernel ≥5.15 for eBPF)

```bash
git clone https://github.com/azdyn7-ai/Project-Supply-Chin.git
cd Project-Supply-Chin/cnd-project

# Step 0: Validate environment
bash scripts/validate_env.sh

# Step 1: Full cluster setup (Minikube + Kyverno + Falco + Tetragon + Prometheus)
bash scripts/setup-cluster.sh

# Step 2: Build SLSA Level 3 pipeline
bash scripts/build_pipeline.sh
# → produces: sbom.cyclonedx.json, provenance.json, allowed_binaries.json

# Step 3: Verify all artifacts
bash scripts/verify_artifacts.sh localhost:5001/cnd-demo-app:latest

# Step 4: Test admission control
bash scripts/test_admission.sh

# Step 5: Run attack simulation (5 runs × 3 scenarios)
bash scripts/simulate_attacks.sh
# → produces: evaluation/results/detection_results.csv

# Step 6: Collect performance metrics (3-mode comparison)
bash scripts/collect_metrics.sh
# → produces: evaluation/results/performance_results.csv

# Step 7: Generate charts + LaTeX tables
pip3 install matplotlib scipy numpy
python3 evaluation/analyze_results.py
# → produces: evaluation/results/charts/*.png, table_detection.tex
```

---

## CI/CD Supply-Chain Pipeline (GitHub Actions)

Two workflows in `.github/workflows/` implement the **build-time** half of the framework.

### `build-sign-sbom.yml` — build → sign → SBOM → provenance → scan

Runs on every push to `main`, on version tags (`v*`), and on demand. For each of the
three services (`cnd-demo-app`, `enrichment-service`, `feedback-service`) it:

1. **Builds** the container with Docker Buildx and pushes it to GHCR.
2. **Signs** it keylessly with **Cosign** (Sigstore — no long-lived keys; the signer
   identity is the GitHub OIDC token, recorded in the Rekor transparency log).
3. **Generates a CycloneDX SBOM** with **Syft** and **attests** it to the image.
4. **Attaches SLSA build provenance** via `actions/attest-build-provenance`
   (the provenance required for **SLSA Level 3**).
5. **Scans** the image with **Grype** and uploads the results (SARIF) to the Security tab.

Pull requests only build the images (no push/sign) to validate the Dockerfiles.

Published images:

```
ghcr.io/azdyn7-ai/project-supply-chin/cnd-demo-app:latest
ghcr.io/azdyn7-ai/project-supply-chin/enrichment-service:latest
ghcr.io/azdyn7-ai/project-supply-chin/feedback-service:latest
```

### `verify-and-deploy.yml` — verification gate

After a successful build (or on demand) it independently re-verifies, from the
consumer side, the same guarantees Kyverno enforces at admission time:

```bash
cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com …
cosign verify-attestation --type cyclonedx …
gh attestation verify oci://<image> --repo azdyn7-ai/Project-Supply-Chin
```

> **Required repository setting:** GitHub → Settings → Actions → General →
> *Workflow permissions* must be **Read and write** so the pipeline can push images
> and write attestations to GHCR. No extra secrets are needed — signing uses the
> built-in `GITHUB_TOKEN` and OIDC.
>
> After the first successful run, set the three GHCR packages to **public**
> (each package → *Package settings* → *Change visibility*) so the cluster can pull
> them with `imagePullPolicy: Always` and no pull secret.

> **SLSA provenance, twice:** the pipeline attaches provenance two ways —
> `actions/attest-build-provenance` (authentic SLSA L3, verified in CI with
> `gh attestation verify`) **and** `cosign attest --type slsaprovenance1` (so
> Kyverno's cosign attestor can verify provenance at admission — Rule 3).

---

## Evaluation Metrics (Chapter 4)

| Metric | Tool | Output |
|--------|------|--------|
| True Positive Rate (TPR) | simulate_attacks.sh | detection_results.csv |
| False Positive Rate (FPR) | simulate_attacks.sh | false_positive_results.csv |
| Detection Latency (ms) | simulate_attacks.sh | detection_results.csv |
| Build time overhead | collect_metrics.sh | performance_results.csv |
| Signing overhead | collect_metrics.sh | performance_results.csv |
| Admission latency | collect_metrics.sh | performance_results.csv |
| CPU/Memory (Falco+Tetragon) | collect_metrics.sh | performance_results.csv |
| Mode A vs B vs C comparison | collect_metrics.sh | comparison_results.csv |
| Statistical significance | analyze_results.py | analysis_summary.json |
| Charts | analyze_results.py | results/charts/*.png |
| LaTeX tables | analyze_results.py | table_detection.tex |

---

## Attack Scenarios

| # | Scenario | Method | Expected Detection |
|---|----------|--------|-------------------|
| S1 | Image tampering | Deploy unsigned image | Kyverno blocks at admission |
| S2 | Runtime shell | kubectl exec bash into container | Falco SBOM rule: shell not in SBOM |
| S3 | Malicious dependency | pip install inside container | Falco SBOM rule: package manager not in SBOM |

**False Positive Test**: 5 clean deployments — zero alerts expected

---

## Tool Versions

| Tool | Version | Role |
|------|---------|------|
| Minikube | latest | 2-node cluster (containerd + Calico) |
| Kyverno | 1.12.6 | Admission control (3 policies) |
| Falco | 4.3.0 | Runtime monitoring (eBPF, SBOM-enriched rules) |
| Tetragon | 1.1.0 | eBPF LSM enforcement + process tracing |
| Cosign | 2.2.4 | Keyless signing (Sigstore/Rekor) |
| Syft | latest | SBOM generation (CycloneDX + SPDX) |
| Grype | latest | CVE scanning |
| Prometheus + Grafana | latest | Performance metrics |
