# PRD-03: ComplianceDB & Tamper-Evident Evidence Vault

> **Status:** APPROVED FOR IMPLEMENTATION
> **Target Sprint:** Sprint 5 & Sprint 6 (Phase 2)
> **Target Service:** services/compliancedb/, migrations/
> **Owner:** Distributed Backend & Data Engineer

---

## 1. Problem & Objectives
- **Problem:** Regulators ask "Were you ever non-compliant? For how long? When did you fix it?" Point-in-time scans cannot prove historical adherence.
- **Solution:** A multi-tenant, org-scoped PostgreSQL ledger using cryptographic hash-chaining (self_hash = SHA256(...)). Append-only permissions guarantee that historical records cannot be altered.

---

## 2. Database Schema (PostgreSQL 15+)

File: migrations/001_compliance_db_init.sql

`sql
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    git_url VARCHAR(512) NOT NULL,
    default_branch VARCHAR(64) NOT NULL DEFAULT 'main',
    UNIQUE(org_id, git_url)
);

CREATE TABLE scan_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id),
    commit_sha VARCHAR(64) NOT NULL,
    branch VARCHAR(128) NOT NULL,
    scan_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    aibom_sha256 VARCHAR(64) NOT NULL,
    components_count INT NOT NULL,
    vulnerabilities_count INT NOT NULL,
    controls_met INT NOT NULL,
    controls_gap INT NOT NULL,
    controls_manual INT NOT NULL,
    prev_snapshot_hash VARCHAR(64),
    self_hash VARCHAR(64) NOT NULL,
    raw_aibom JSONB NOT NULL
);

-- Immutable append-only rule for scan snapshots
REVOKE UPDATE, DELETE ON scan_snapshots FROM api_role;

CREATE TABLE compliance_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id),
    control_id VARCHAR(128) NOT NULL,
    statute_ref VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN',
    opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    opening_snapshot_id UUID NOT NULL REFERENCES scan_snapshots(id),
    resolved_at TIMESTAMPTZ,
    resolving_snapshot_id UUID REFERENCES scan_snapshots(id),
    resolution_duration_hours NUMERIC GENERATED ALWAYS AS (
        EXTRACT(EPOCH FROM (resolved_at - opened_at)) / 3600
    ) STORED
);
`

---

## 3. Cryptographic Hash-Chain Implementation

File: services/compliancedb/snapshot.go

`go
package compliancedb

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

func ComputeSnapshotHash(
	repoID string,
	commitSHA string,
	ts time.Time,
	aibomSHA string,
	met, gap, manual int,
	prevHash string,
) string {
	payload := fmt.Sprintf(
		"%s|%s|%s|%s|%d:%d:%d|%s",
		repoID,
		commitSHA,
		ts.UTC().Format(time.RFC3339),
		aibomSHA,
		met, gap, manual,
		prevHash,
	)
	sum := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(sum[:])
}
`

---

## 4. Acceptance Criteria
1. TestHashChainIntegrity: Modifying any byte in a past snapshot invalidates all child prev_snapshot_hash validations.
2. PostgreSQL database user pi_role receives SQL permission denied on UPDATE scan_snapshots.
3. Incident duration automatically computed on resolution scan.
