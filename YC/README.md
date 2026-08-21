# AIROM Compliance Platform — YC Project Hub

> **One-Liner:** AI-native compliance software that watches regulations across all 50 US states, flags anomalies, enables renewal filings, and writes audit reports — replacing 80% of compliance grunt work.

---

## 📁 Repository & Document Index

| Document | Description |
|---|---|
| [**01_EXECUTIVE_PITCH_AND_VISION.md**](./01_EXECUTIVE_PITCH_AND_VISION.md) | YC Application & Pitch narrative: Problem, Solution, Why Now, Market (→), Business Model, Moats. |
| [**02_ARCHITECTURE_AND_SYSTEM_DESIGN.md**](./02_ARCHITECTURE_AND_SYSTEM_DESIGN.md) | Full 5-Layer technical architecture: Scanner Core, RegWatch, ComplianceDB, AnomalyEngine, ReportEngine, FilingAgent. Data boundaries & invariants. |
| [**03_PRODUCT_PLAN_AND_SPECIFICATION.md**](./03_PRODUCT_PLAN_AND_SPECIFICATION.md) | Complete product plan with YAML schemas, concrete \.airomapproved\ specification, wireframes for Green/Yellow/Red filing gates. |
| [**04_ROADMAP_AND_MILESTONES.md**](./04_ROADMAP_AND_MILESTONES.md) | 12-Month Execution Roadmap (Months 0-3, 3-6, 6-9, 9-12) with explicit exit criteria, deliverable checklists, and resource allocations. |
| [**05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md**](./05_COMPLIANCE_AND_REGULATORY_LANDSCAPE.md) | 50-State regulatory matrix (CA, CO, NY, IL, TX, VA), enforcement trends, statutory requirements mapped to AIBOM evidence. |

---

## 🛠 Local Codebase & Setup

- **Forked Repo:** https://github.com/dharmik136/airom
- **Local Path:** \C:\Users\remoteadmin\airom- **Core Binary:** Single static Go binary (\CGO_ENABLED=0\), Apache 2.0 license.
- **Upstream:** https://github.com/airomhq/airom

---

## ⚡ Quick Start & Verification

Run a live scan on your project:
\\ash
# 1. Install scanner (pure Go binary / pip wheel)
pip install airom

# 2. Scan codebase with instant AIBOM + CVE + NIST mapping
airom scan .

# 3. Output machine-readable CycloneDX / JSON
airom scan . -o json=aibom.json -o sarif=results.sarif
\