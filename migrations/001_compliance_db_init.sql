-- =============================================================================
-- Migration: 001_compliance_db_init.sql
-- Description: ComplianceDB & Tamper-Evident Evidence Vault Schema
-- Target: PostgreSQL 15+
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. Repositories
CREATE TABLE IF NOT EXISTS repositories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    git_url VARCHAR(512) NOT NULL,
    default_branch VARCHAR(64) NOT NULL DEFAULT 'main',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(org_id, git_url)
);

-- 3. Scan Snapshots (Append-Only Cryptographic Hash Ledger)
CREATE TABLE IF NOT EXISTS scan_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE RESTRICT,
    commit_sha VARCHAR(64) NOT NULL,
    branch VARCHAR(128) NOT NULL,
    scan_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    aibom_sha256 VARCHAR(64) NOT NULL,
    components_count INT NOT NULL DEFAULT 0,
    vulnerabilities_count INT NOT NULL DEFAULT 0,
    controls_met INT NOT NULL DEFAULT 0,
    controls_gap INT NOT NULL DEFAULT 0,
    controls_manual INT NOT NULL DEFAULT 0,
    prev_snapshot_hash VARCHAR(64),
    self_hash VARCHAR(64) NOT NULL,
    raw_aibom JSONB NOT NULL
);

-- 4. Control Evaluations
CREATE TABLE IF NOT EXISTS control_evaluations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID NOT NULL REFERENCES scan_snapshots(id) ON DELETE CASCADE,
    control_id VARCHAR(128) NOT NULL,
    statute_ref VARCHAR(255) NOT NULL,
    verdict VARCHAR(32) NOT NULL, -- 'met', 'gap', 'manual'
    gap_message TEXT,
    remediation_url TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. Compliance Incidents (Auto-Computed Duration)
CREATE TABLE IF NOT EXISTS compliance_incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE RESTRICT,
    control_id VARCHAR(128) NOT NULL,
    statute_ref VARCHAR(255) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'OPEN', -- 'OPEN', 'RESOLVED'
    opened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    opening_snapshot_id UUID NOT NULL REFERENCES scan_snapshots(id),
    resolved_at TIMESTAMPTZ,
    resolving_snapshot_id UUID REFERENCES scan_snapshots(id),
    resolution_duration_hours NUMERIC GENERATED ALWAYS AS (
        EXTRACT(EPOCH FROM (resolved_at - opened_at)) / 3600
    ) STORED
);

-- 6. Filing Audit Log
CREATE TABLE IF NOT EXISTS filing_audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE RESTRICT,
    regulation_id VARCHAR(128) NOT NULL,
    action VARCHAR(64) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    payload JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for fast query lookup
CREATE INDEX IF NOT EXISTS idx_repositories_org_id ON repositories(org_id);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_repo_ts ON scan_snapshots(repo_id, scan_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scan_snapshots_self_hash ON scan_snapshots(self_hash);
CREATE INDEX IF NOT EXISTS idx_control_evaluations_snapshot_id ON control_evaluations(snapshot_id);
CREATE INDEX IF NOT EXISTS idx_compliance_incidents_repo_status ON compliance_incidents(repo_id, status);
CREATE INDEX IF NOT EXISTS idx_filing_audit_log_repo_ts ON filing_audit_log(repo_id, timestamp DESC);

-- Security: Immutable append-only rule for scan snapshots and filing audit logs
DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'api_role') THEN
        REVOKE UPDATE, DELETE ON scan_snapshots, filing_audit_log FROM api_role;
    END IF;
END
$$;
