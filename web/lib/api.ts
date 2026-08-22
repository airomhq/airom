import {
  UserSession,
  OrgComplianceOverview,
  RepositorySummary,
  ScanSnapshot,
  FrameworkCompliance,
  AttestationPayload,
  AttestationResult,
  AnomalyEvent,
} from "../types";

const API_BASE = typeof window !== "undefined" ? "" : (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080");

class ApiClient {
  private token: string | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };

    if (this.token) {
      headers["Authorization"] = `Bearer ${this.token}`;
    }

    const res = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
    });

    if (!res.ok) {
      let errorMsg = `API Error: ${res.status} ${res.statusText}`;
      try {
        const errJson = await res.json();
        if (errJson.error) errorMsg = errJson.error;
      } catch {
        // Fallback to generic message
      }
      throw new Error(errorMsg);
    }

    return res.json();
  }

  async loginWithApiKey(apiKey: string): Promise<UserSession> {
    const session = await this.request<UserSession>("/api/v1/auth/token", {
      method: "POST",
      body: JSON.stringify({ api_key: apiKey }),
    });
    this.setToken(session.token);
    return session;
  }

  async getOrgCompliance(orgId: string): Promise<OrgComplianceOverview> {
    return this.request<OrgComplianceOverview>(`/api/v1/orgs/${encodeURIComponent(orgId)}/compliance`);
  }

  async getRepositories(orgId: string): Promise<RepositorySummary[]> {
    return this.request<RepositorySummary[]>(`/api/v1/orgs/${encodeURIComponent(orgId)}/repos`);
  }

  async getRepoHistory(repoId: string): Promise<ScanSnapshot[]> {
    return this.request<ScanSnapshot[]>(`/api/v1/repos/${encodeURIComponent(repoId)}/history`);
  }

  async getRepoCompliance(repoId: string): Promise<FrameworkCompliance[]> {
    return this.request<FrameworkCompliance[]>(`/api/v1/repos/${encodeURIComponent(repoId)}/compliance`);
  }

  async submitAttestation(repoId: string, payload: AttestationPayload): Promise<AttestationResult> {
    return this.request<AttestationResult>(`/api/v1/repos/${encodeURIComponent(repoId)}/attest`, {
      method: "POST",
      body: JSON.stringify(payload),
    });
  }

  async getAnomalies(orgId: string): Promise<AnomalyEvent[]> {
    return this.request<AnomalyEvent[]>(`/api/v1/orgs/${encodeURIComponent(orgId)}/anomalies`);
  }
}

export const api = new ApiClient();
