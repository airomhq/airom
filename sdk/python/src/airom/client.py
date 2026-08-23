"""
AIROM Enterprise Python SDK Client
Provides programmatic access to AIROM ComplianceDB, ledger verification,
scan orchestration, and real-time governance stream.
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional


class AIROMClient:
    """
    Client for interacting with the AIROM Enterprise Governance & Compliance API.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_key: Optional[str] = None,
        timeout: int = 15,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "airom-python-sdk/1.0.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        req_data = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(
            url=url,
            data=req_data,
            headers=self._headers(),
            method=method,
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_bytes = resp.read()
                if resp_bytes:
                    return json.loads(resp_bytes.decode("utf-8"))
                return {}
        except urllib.error.HTTPError as err:
            err_body = err.read().decode("utf-8") if err.fp else ""
            raise RuntimeError(
                f"AIROM API Error ({err.code}): {err.reason} - {err_body}"
            ) from err
        except urllib.error.URLError as err:
            raise ConnectionError(f"Failed to connect to AIROM at {url}: {err.reason}") from err

    def get_compliance_status(self, org_id: str) -> Dict[str, Any]:
        """
        Fetch high-level compliance aggregation across all repositories in an organization.
        """
        return self._request("GET", f"/api/v1/orgs/{org_id}/compliance")

    def get_snapshot_history(self, repo_id: str) -> List[Dict[str, Any]]:
        """
        Retrieve chronological hash-chain snapshot ledger for a repository.
        """
        result = self._request("GET", f"/api/v1/repos/{repo_id}/history")
        return result.get("snapshots", [])

    def ingest_snapshot(
        self,
        repo_id: str,
        scan_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Ingest a new scan snapshot and atomically append it to the unbroken SHA-256 hash ledger.
        """
        return self._request("POST", f"/api/v1/repos/{repo_id}/snapshots", data=scan_payload)

    def verify_chain_integrity(self, repo_id: str) -> Dict[str, Any]:
        """
        Perform zero-trust cryptographic audit over the repository's snapshot chain.
        """
        return self._request("GET", f"/api/v1/repos/{repo_id}/verify")

    def attest_control(
        self,
        repo_id: str,
        control_id: str,
        decision: str,
        attester: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Sign a manual governance attestation (green / yellow / red review).
        """
        payload = {
            "control_id": control_id,
            "decision": decision,
            "attester": attester,
            "notes": notes,
        }
        return self._request("POST", f"/api/v1/repos/{repo_id}/attest", data=payload)
