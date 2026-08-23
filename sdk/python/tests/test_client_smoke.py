"""
Smoke tests and API contract verification for AIROMClient Python SDK.

Validates:
- Client import, initialization, header handling, base URL normalization.
- get_compliance_status request routing and JSON response decoding.
- get_snapshot_history snapshot array extraction and fallback.
- ingest_snapshot payload serialization, POST routing, response parsing.
- verify_chain_integrity zero-trust verification request and response parsing.
- attest_control governance attestation payload construction and submission.
- Error handling: HTTP error mapping to RuntimeError, ConnectionError on network failures,
  and graceful handling of empty response bodies.
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

import pytest

import airom
from airom.client import AIROMClient


class MockAIROMHandler(BaseHTTPRequestHandler):
    """
    Mock HTTP handler simulating AIROM Enterprise ComplianceDB REST endpoints.
    Records received requests and returns predefined responses.
    """

    # Shared records for test inspection
    requests_log: list[dict[str, Any]] = []
    custom_responses: dict[str, Any] = {}
    custom_status_codes: dict[str, int] = {}

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress standard HTTP server console logging during test runs
        pass

    def _record_request(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""
        parsed_body = None
        if body:
            try:
                parsed_body = json.loads(body)
            except Exception:
                parsed_body = body

        # Normalize header keys to lowercase for robust assertion
        headers_lower = {k.lower(): v for k, v in self.headers.items()}

        req_record = {
            "method": self.command,
            "path": self.path,
            "headers": headers_lower,
            "raw_body": body,
            "json_body": parsed_body,
        }
        self.requests_log.append(req_record)
        return req_record

    def do_GET(self) -> None:
        _ = self._record_request()
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        status_code = self.custom_status_codes.get(path, 200)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if status_code >= 400:
            err_resp = self.custom_responses.get(path, {"error": "Mocked Error", "path": path})
            self.wfile.write(json.dumps(err_resp).encode("utf-8"))
            return

        if path in self.custom_responses:
            resp_data = self.custom_responses[path]
            if resp_data is not None:
                self.wfile.write(json.dumps(resp_data).encode("utf-8"))
            return

        # Default route handling
        if path.startswith("/api/v1/orgs/") and path.endswith("/compliance"):
            org_id = path.split("/")[4]
            response = {
                "org_id": org_id,
                "total_repos": 3,
                "total_met": 24,
                "total_gaps": 0,
                "total_manual": 2,
                "regulations": [
                    {
                        "regulation_id": "colorado-ai-act",
                        "met_count": 12,
                        "gap_count": 0,
                        "manual_count": 1,
                        "total_repos": 3,
                    },
                    {
                        "regulation_id": "illinois-bipa",
                        "met_count": 12,
                        "gap_count": 0,
                        "manual_count": 1,
                        "total_repos": 3,
                    },
                ],
                "generated_at": "2026-08-23T15:00:00Z",
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))

        elif path.startswith("/api/v1/repos/") and path.endswith("/history"):
            repo_id = path.split("/")[4]
            response = {
                "repo_id": repo_id,
                "snapshots": [
                    {
                        "id": f"snap-{repo_id}-001",
                        "commit_sha": "a1b2c3d4e5f6",
                        "branch": "main",
                        "scan_timestamp": "2026-08-23T14:00:00Z",
                        "self_hash": (
                            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        ),
                        "prev_snapshot_hash": "",
                        "components_count": 18,
                        "controls_met": 10,
                        "controls_gap": 0,
                        "controls_manual": 1,
                    }
                ],
                "total_count": 1,
                "generated_at": "2026-08-23T15:00:00Z",
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))

        elif path.startswith("/api/v1/repos/") and path.endswith("/verify"):
            response = {
                "valid": True,
                "total_snapshots": 5,
                "broken_at_index": -1,
                "broken_snapshot": None,
                "violations": [],
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
        else:
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))

    def do_POST(self) -> None:
        _ = self._record_request()
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        status_code = self.custom_status_codes.get(path, 200)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        if status_code >= 400:
            err_resp = self.custom_responses.get(path, {"error": "Mocked Post Error", "path": path})
            self.wfile.write(json.dumps(err_resp).encode("utf-8"))
            return

        if path in self.custom_responses:
            resp_data = self.custom_responses[path]
            if resp_data is not None:
                self.wfile.write(json.dumps(resp_data).encode("utf-8"))
            return

        if path.startswith("/api/v1/repos/") and path.endswith("/snapshots"):
            repo_id = path.split("/")[4]
            response = {
                "snapshot_id": f"snap-{repo_id}-test-99",
                "self_hash": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                "prev_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "new_incidents_count": 0,
                "resolved_incidents": [],
                "chain_status": "VALID",
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))

        elif path.startswith("/api/v1/repos/") and path.endswith("/attest"):
            response = {
                "status": "ATTESTATION_RECORDED",
                "signature": "hmac-sha256-verified-signature-string",
                "timestamp": "2026-08-23T15:00:00Z",
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))
        else:
            self.wfile.write(json.dumps({"status": "received"}).encode("utf-8"))


@pytest.fixture
def mock_server():
    """Spin up an ephemeral mock HTTP server on localhost."""
    MockAIROMHandler.requests_log = []
    MockAIROMHandler.custom_responses = {}
    MockAIROMHandler.custom_status_codes = {}

    server = HTTPServer(("127.0.0.1", 0), MockAIROMHandler)
    port = server.server_port
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    base_url = f"http://127.0.0.1:{port}"
    yield base_url, MockAIROMHandler

    server.shutdown()
    server.server_close()


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------


def test_client_import_and_initialization():
    """Verify AIROMClient is exported in root module and initializes cleanly."""
    assert hasattr(airom, "AIROMClient")
    assert airom.AIROMClient is AIROMClient

    # Default values
    default_client = AIROMClient()
    assert default_client.base_url == "http://localhost:8080"
    assert default_client.api_key is None
    assert default_client.timeout == 15

    # Custom values with trailing slash normalization
    custom_client = AIROMClient(
        base_url="https://compliance.enterprise.airom.internal///",
        api_key="airom_live_sec_token_9999",
        timeout=45,
    )
    assert custom_client.base_url == "https://compliance.enterprise.airom.internal"
    assert custom_client.api_key == "airom_live_sec_token_9999"
    assert custom_client.timeout == 45


def test_client_headers_composition():
    """Assert standard headers and conditional Authorization Bearer header."""
    unauthenticated_client = AIROMClient(base_url="http://localhost:8080")
    headers = unauthenticated_client._headers()
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"
    assert headers["User-Agent"] == "airom-python-sdk/1.0.0"
    assert "Authorization" not in headers

    authenticated_client = AIROMClient(
        base_url="http://localhost:8080",
        api_key="airom_live_api_key_test_xyz",
    )
    auth_headers = authenticated_client._headers()
    assert auth_headers["Authorization"] == "Bearer airom_live_api_key_test_xyz"
    assert auth_headers["User-Agent"] == "airom-python-sdk/1.0.0"


def test_get_compliance_status(mock_server):
    """Assert get_compliance_status issues GET to /api/v1/orgs/{org_id}/compliance."""
    base_url, handler = mock_server
    client = AIROMClient(base_url=base_url, api_key="test-api-key")

    resp = client.get_compliance_status(org_id="org-acme-corp")

    assert len(handler.requests_log) == 1
    req = handler.requests_log[0]
    assert req["method"] == "GET"
    assert req["path"] == "/api/v1/orgs/org-acme-corp/compliance"
    assert req["headers"].get("authorization") == "Bearer test-api-key"
    assert req["headers"].get("user-agent") == "airom-python-sdk/1.0.0"

    assert resp["org_id"] == "org-acme-corp"
    assert resp["total_repos"] == 3
    assert resp["total_met"] == 24
    assert len(resp["regulations"]) == 2
    assert resp["regulations"][0]["regulation_id"] == "colorado-ai-act"


def test_get_snapshot_history(mock_server):
    """Assert get_snapshot_history issues GET to /api/v1/repos/{repo_id}/history."""
    base_url, handler = mock_server
    client = AIROMClient(base_url=base_url, api_key="test-api-key")

    snapshots = client.get_snapshot_history(repo_id="repo-vision-ai")

    assert len(handler.requests_log) == 1
    req = handler.requests_log[0]
    assert req["method"] == "GET"
    assert req["path"] == "/api/v1/repos/repo-vision-ai/history"

    assert isinstance(snapshots, list)
    assert len(snapshots) == 1
    snap = snapshots[0]
    assert snap["id"] == "snap-repo-vision-ai-001"
    assert snap["commit_sha"] == "a1b2c3d4e5f6"
    assert snap["controls_met"] == 10


def test_get_snapshot_history_empty_fallback(mock_server):
    """Assert get_snapshot_history safely defaults to empty list if no snapshots key."""
    base_url, handler = mock_server
    client = AIROMClient(base_url=base_url)

    handler.custom_responses["/api/v1/repos/repo-empty/history"] = {"repo_id": "repo-empty"}
    snapshots = client.get_snapshot_history(repo_id="repo-empty")

    assert snapshots == []


def test_ingest_snapshot(mock_server):
    """Assert ingest_snapshot serializes payload and POSTs to /api/v1/repos/{repo_id}/snapshots."""
    base_url, handler = mock_server
    client = AIROMClient(base_url=base_url, api_key="ci-token-007")

    scan_payload = {
        "commit_sha": "d4e5f6a1b2c3",
        "branch": "feature/bipa-controls",
        "aibom_sha256": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
        "components_count": 22,
        "controls_met": 15,
        "controls_gap": 0,
        "controls_manual": 2,
    }

    resp = client.ingest_snapshot(repo_id="repo-biometrics", scan_payload=scan_payload)

    assert len(handler.requests_log) == 1
    req = handler.requests_log[0]
    assert req["method"] == "POST"
    assert req["path"] == "/api/v1/repos/repo-biometrics/snapshots"
    assert req["headers"].get("content-type") == "application/json"
    assert req["json_body"] == scan_payload

    assert resp["chain_status"] == "VALID"
    assert resp["snapshot_id"] == "snap-repo-biometrics-test-99"
    assert "self_hash" in resp


def test_verify_chain_integrity(mock_server):
    """Assert verify_chain_integrity issues GET to /api/v1/repos/{repo_id}/verify."""
    base_url, handler = mock_server
    client = AIROMClient(base_url=base_url)

    resp = client.verify_chain_integrity(repo_id="repo-nlp-agent")

    assert len(handler.requests_log) == 1
    req = handler.requests_log[0]
    assert req["method"] == "GET"
    assert req["path"] == "/api/v1/repos/repo-nlp-agent/verify"

    assert resp["valid"] is True
    assert resp["total_snapshots"] == 5
    assert resp["broken_at_index"] == -1


def test_attest_control(mock_server):
    """Assert attest_control formats governance attestation payload and POSTs to /attest."""
    base_url, handler = mock_server
    client = AIROMClient(base_url=base_url, api_key="lead-auditor-key")

    resp = client.attest_control(
        repo_id="repo-fraud-detector",
        control_id="BIPA-740-ILCS-14-15-E",
        decision="met",
        attester="auditor@airom.test",
        notes="Validated cryptographic erasure and 3-year data destruction policy.",
    )

    assert len(handler.requests_log) == 1
    req = handler.requests_log[0]
    assert req["method"] == "POST"
    assert req["path"] == "/api/v1/repos/repo-fraud-detector/attest"

    expected_payload = {
        "control_id": "BIPA-740-ILCS-14-15-E",
        "decision": "met",
        "attester": "auditor@airom.test",
        "notes": "Validated cryptographic erasure and 3-year data destruction policy.",
    }
    assert req["json_body"] == expected_payload

    assert resp["status"] == "ATTESTATION_RECORDED"
    assert "signature" in resp


def test_http_error_handling(mock_server):
    """Assert HTTP 4xx/5xx responses raise RuntimeError with formatted diagnostics."""
    base_url, handler = mock_server
    client = AIROMClient(base_url=base_url)

    handler.custom_status_codes["/api/v1/orgs/org-forbidden/compliance"] = 403
    handler.custom_responses["/api/v1/orgs/org-forbidden/compliance"] = {
        "error": "insufficient_permissions",
        "message": "API key lacks PermLedgerVerify role",
    }

    with pytest.raises(RuntimeError) as exc_info:
        client.get_compliance_status("org-forbidden")

    err_msg = str(exc_info.value)
    assert "AIROM API Error (403)" in err_msg
    assert "insufficient_permissions" in err_msg


def test_connection_error_handling():
    """Assert network connection failures raise ConnectionError with endpoint details."""
    # Find an unused local port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    unused_port = s.getsockname()[1]
    s.close()

    client = AIROMClient(base_url=f"http://127.0.0.1:{unused_port}", timeout=1)

    with pytest.raises(ConnectionError) as exc_info:
        client.get_compliance_status("org-offline")

    assert "Failed to connect to AIROM at" in str(exc_info.value)


def test_empty_response_handling(mock_server):
    """Assert empty response body (e.g. 204 or empty string) returns empty dict."""
    base_url, handler = mock_server
    client = AIROMClient(base_url=base_url)

    handler.custom_responses["/api/v1/repos/repo-204/verify"] = None
    resp = client.verify_chain_integrity("repo-204")
    assert resp == {}
