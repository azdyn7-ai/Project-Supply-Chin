# Project-Cloud Software Supply Chain

**An Integrated Cloud Software Supply-Chain Security Framework** — combining SLSA
provenance, Sigstore/Cosign signing, and SBOMs at build time with continuous
runtime verification (Kyverno admission control + Falco/Tetragon eBPF monitoring).

> Bachelor's Graduation Project — Computer Network Engineering & Distributed Systems
> Taiz University, Faculty of Engineering & IT.

The full project lives in [`cnd-project/`](cnd-project/). Start with its
[README](cnd-project/README.md) for the architecture, run guide, and evaluation.

---

## What's inside

```
Project-Supply-Chin/
├── .github/workflows/          # CI/CD supply-chain pipeline (GitHub Actions)
│   ├── build-sign-sbom.yml     # build → cosign sign → syft SBOM → SLSA → grype
│   └── verify-and-deploy.yml   # cosign / SLSA verification gate
└── cnd-project/
    ├── app/                    # Go demo microservice (+ Flask demo for quick runs)
    ├── enrichment-service/     # ★ Provenance bridge (build-time → runtime)
    ├── feedback-service/       # Runtime → build feedback loop
    ├── kubernetes/             # Kyverno policies, Falco, Tetragon, monitoring
    ├── scripts/                # setup, build pipeline, attack sims, metrics
    └── evaluation/             # results analysis + Chapter 4 templates
```

## Try it in 30 seconds

The demo microservice exposes `/health`, `/version`, and `/api/data`. On Replit it
runs automatically on port **5000**:

```bash
python cnd-project/app/main.py       # Flask demo   → http://localhost:5000
# …or the Go service:
cd cnd-project/app && go run .        # Go service   → http://localhost:8080
```

## The pipeline

Pushing to `main` triggers [`build-sign-sbom.yml`](.github/workflows/build-sign-sbom.yml),
which builds each service image, signs it with Cosign (keyless/Sigstore), generates a
CycloneDX SBOM with Syft, attaches SLSA build provenance, and scans it with Grype.
[`verify-and-deploy.yml`](.github/workflows/verify-and-deploy.yml) then re-verifies the
signature, SBOM attestation, and provenance before deployment.

See [`cnd-project/README.md`](cnd-project/README.md) for the complete guide.
