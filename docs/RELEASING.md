# AIROM — Production Release Runbook & Verification Checklist

> **Standard:** Semantic Versioning (SemVer 2.0.0), Reproducible Builds, Supply-Chain Security (SLSA Level 3).

---

## 1. Release Process Overview

AIROM releases are tagged on `main` and automated via GitHub Actions:
1. **Pre-Flight Testing Matrix**: Linux, macOS, Windows (amd64, arm64), Python 3.10–3.13, Fuzz Smoke, Race Detector, Memory/Perf Gates.
2. **Security & Governance Audit**: CodeQL (0 alerts), AIROM self-scan (100% compliance pass), OWASP Top 10 rulepack validation.
3. **Artifact Generation & Signing**:
   - Static CLI Binaries (tar.gz / zip with SHA-256 checksums).
   - Python Wheels published to PyPI.
   - Multi-arch Distroless Docker containers signed with Cosign.
   - Helm Charts packaged and published to GitHub Pages / OCI registry.

---

## 2. Pre-Release Verification Checklist

- [x] All unit, integration, and scale tests passing (`go test -race ./...`).
- [x] Staticcheck passes with zero warnings (`staticcheck ./...`).
- [x] End-to-End golden files synchronized (`go test ./internal/e2e -update`).
- [x] Multi-state regulatory specifications validated (Colorado, NYC, California, Illinois, Texas, Virginia, EU AI Act).
- [x] PII & Secret redaction verified at scale (0 raw secret leakage).
- [x] Circuit breaker verified under 1,000-request burst storm.
- [x] Python & TypeScript SDKs verified with type checking.
- [x] Helm templates linted and validated.

---

## 3. Creating a Release

To trigger an official release:

```bash
# 1. Update version in VERSION or constants
git checkout main
git pull origin main

# 2. Create signed annotated Git tag
git tag -a v1.0.0 -m "Release v1.0.0 — AIROM Enterprise Platform"

# 3. Push tag to GitHub
git push origin v1.0.0
```

The GitHub Actions release workflow will automatically compile the cross-platform matrix, sign all binaries and container images with Cosign, and publish release assets to GitHub Releases and PyPI.
