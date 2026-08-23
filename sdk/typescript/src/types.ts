export type ComponentKind =
  | 'hosted_llm'
  | 'local_model'
  | 'framework'
  | 'agent_framework'
  | 'infra'
  | 'vector_db'
  | 'dataset'
  | 'training_data'
  | 'prompt'
  | 'eval_dataset';

export type ComplianceVerdict = 'met' | 'gap' | 'manual_review';

export interface Location {
  path: string;
  line?: number;
}

export interface Occurrence {
  location: Location;
  detector_id: string;
  method: string;
  confidence: number;
  snippet?: string;
  fields?: Record<string, string>;
}

export interface Component {
  id: string;
  name: string;
  kind: ComponentKind;
  version?: string;
  provider?: string;
  confidence: number;
  evidence: {
    occurrences: Occurrence[];
  };
}

export interface Inventory {
  schema_version: string;
  created_at: string;
  components: Component[];
}

export interface Snapshot {
  id: string;
  repo_id: string;
  org_id: string;
  parent_hash: string;
  snapshot_hash: string;
  timestamp: string;
  components_count: number;
  compliance_met_count: number;
  compliance_gap_count: number;
}

export interface OrgComplianceSummary {
  org_id: string;
  total_repositories: number;
  total_components: number;
  overall_score: number;
  frameworks: Record<string, {
    met: number;
    gap: number;
    manual_review: number;
  }>;
}

export interface AttestationPayload {
  control_id: string;
  decision: 'met' | 'gap' | 'exempt';
  attester: string;
  notes?: string;
}

export interface ClientConfig {
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
}
