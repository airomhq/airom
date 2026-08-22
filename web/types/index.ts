export type UserRole = "admin" | "compliance_officer" | "developer" | "auditor";

export interface UserSession {
  userId: string;
  email: string;
  role: UserRole;
  orgId: string;
  token: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  tier: "community" | "team" | "enterprise";
  monthlyScanLimit: number;
  scansUsedThisMonth: number;
  createdAt: string;
}

export interface RepositorySummary {
  id: string;
  name: string;
  orgId: string;
  defaultBranch: string;
  lastScanAt: string;
  lastSnapshotHash: string;
  totalComponents: number;
  complianceRate: number; // 0.0 - 1.0
  activeGaps: number;
  status: "compliant" | "warning" | "non_compliant";
}

export interface ControlEvaluation {
  id: string;
  frameworkId: string;
  title: string;
  category: string;
  state: "met" | "gap" | "manual";
  score: number; // 1.0 = met, 0.0 = gap, null = manual
  rationale: string;
  evidence: Array<{
    componentId: string;
    name: string;
    purl?: string;
    location: string;
    confidence: number;
  }>;
  counterEvidence?: Array<{
    componentId: string;
    name: string;
    risk: string;
    location: string;
  }>;
}

export interface FrameworkCompliance {
  frameworkId: string;
  name: string;
  version: string;
  authority: string;
  metCount: number;
  gapCount: number;
  manualCount: number;
  complianceRate: number; // met / (met + gap)
  controls: ControlEvaluation[];
}

export interface OrgComplianceOverview {
  orgId: string;
  monitoredRepos: number;
  totalAIComponents: number;
  globalComplianceRate: number;
  frameworks: FrameworkCompliance[];
  recentAnomalies: AnomalyEvent[];
}

export interface ScanSnapshot {
  scanId: string;
  repoId: string;
  timestamp: string;
  aibomHash: string;
  controlsHash: string;
  prevHash: string;
  selfHash: string;
  componentsCount: number;
  metCount: number;
  gapCount: number;
  manualCount: number;
}

export interface AnomalyEvent {
  id: string;
  repoId: string;
  repoName: string;
  type: "shadow-ai" | "model-swap" | "config-drift" | "proximity-hiring" | "proximity-credit" | "proximity-healthcare";
  severity: "HIGH" | "MEDIUM" | "LOW";
  componentName: string;
  purl?: string;
  location: string;
  details: string;
  timestamp: string;
}

export interface AttestationPayload {
  frameworkId: string;
  snapshotId: string;
  signerEmail: string;
  signerTitle: string;
  attestations: Record<string, string>; // controlId -> attestation statement
}

export interface AttestationResult {
  attestationToken: string;
  signedAt: string;
  downloadUrl: string;
}
