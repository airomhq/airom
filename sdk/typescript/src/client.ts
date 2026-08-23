import type {
  ClientConfig,
  OrgComplianceSummary,
  Snapshot,
  AttestationPayload,
  Inventory,
} from './types.js';

export class AIROMClient {
  private readonly baseUrl: string;
  private readonly apiKey?: string;
  private readonly timeout: number;

  constructor(config: ClientConfig = {}) {
    this.baseUrl = (config.baseUrl || 'http://localhost:8080').replace(/\/+$/, '');
    this.apiKey = config.apiKey;
    this.timeout = config.timeout || 15000;
  }

  private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'airom-typescript-sdk/1.0.0',
    };

    if (this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new Error(`AIROM API Error (${response.status}): ${response.statusText} - ${errorText}`);
      }

      if (response.status === 204) {
        return {} as T;
      }

      return (await response.json()) as T;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Aggregates organization-wide regulatory compliance across all repos.
   */
  async getComplianceStatus(orgId: string): Promise<OrgComplianceSummary> {
    return this.request<OrgComplianceSummary>('GET', `/api/v1/orgs/${encodeURIComponent(orgId)}/compliance`);
  }

  /**
   * Retrieves the immutable hash-chain snapshot ledger for a repository.
   */
  async getSnapshotHistory(repoId: string): Promise<Snapshot[]> {
    const result = await this.request<{ snapshots: Snapshot[] }>('GET', `/api/v1/repos/${encodeURIComponent(repoId)}/history`);
    return result.snapshots || [];
  }

  /**
   * Ingests a new AIBOM scan snapshot into the unbroken ledger.
   */
  async ingestSnapshot(repoId: string, inventory: Inventory | Record<string, unknown>): Promise<Snapshot> {
    return this.request<Snapshot>('POST', `/api/v1/repos/${encodeURIComponent(repoId)}/snapshots`, inventory);
  }

  /**
   * Zero-trust cryptographic verification of the snapshot hash chain.
   */
  async verifyChainIntegrity(repoId: string): Promise<{ valid: boolean; verified_snapshots: number }> {
    return this.request<{ valid: boolean; verified_snapshots: number }>('GET', `/api/v1/repos/${encodeURIComponent(repoId)}/verify`);
  }

  /**
   * Submits a signed manual attestation for an AI governance control.
   */
  async attestControl(repoId: string, attestation: AttestationPayload): Promise<{ status: string; signature: string }> {
    return this.request<{ status: string; signature: string }>('POST', `/api/v1/repos/${encodeURIComponent(repoId)}/attest`, attestation);
  }
}
