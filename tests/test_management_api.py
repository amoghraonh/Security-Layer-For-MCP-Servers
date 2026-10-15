"""Tests for the localhost read-only management endpoints and static frontend assets."""

from __future__ import annotations

import json
from pathlib import Path

import anyio
from fastapi.testclient import TestClient

from app.api.management import create_management_app
from app.audit.sqlite_audit import sanitize_arguments
from app.gateway.gateway_client import GatewayMCPClient


def test_argument_sanitization_and_sqlite_round_trip(tmp_path: Path) -> None:
    database_path = tmp_path / "sanitization-audit.db"
    app = create_management_app(database_path)
    client = TestClient(app)

    event_id = app.state if hasattr(app, "state") else None
    sanitized = sanitize_arguments({
        "token": "ghp_secret_token_1234567890",
        "nested": {"password": "confidential_password"},
        "safe": "value",
    })
    from app.audit.sqlite_audit import SQLiteAuditLog
    audit_log = SQLiteAuditLog(database_path)
    audit_log.record_event(
        server_identifier="github-mcp-server",
        tool_identifier="get_file_contents",
        arguments={"token": "ghp_secret_token_1234567890", "nested": {"password": "confidential_password"}, "safe": "value"},
        decision="allow",
        matched_policy="AIRLOCK-READ-PERMIT-001",
        reason="Sanitization unit test",
        fingerprint_status="approved",
        response_inspection_outcome="clean",
        upstream_executed=True,
    )
    event = client.get(f"/api/events/{1}").json()
    assert event["sanitized_arguments"] == {
        "token": "[REDACTED]",
        "nested": {"password": "[REDACTED]"},
        "safe": "value",
    }
    assert sanitize_arguments({"api_key": "secret"}) == {"api_key": "[REDACTED]"}


def test_real_mcp_call_is_persisted_and_returned_by_management_api(tmp_path: Path) -> None:
    database_path = tmp_path / "gateway-audit.db"

    async def call_gateway() -> None:
        async with GatewayMCPClient({"SENTRY_X_AUDIT_DATABASE": str(database_path)}).session() as session:
            result = await session.call_tool("get_me", {})
            assert result.is_error is False

    anyio.run(call_gateway)

    app = create_management_app(database_path)
    with TestClient(app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        events = client.get("/api/events")
        assert events.status_code == 200
        event = events.json()[0]
        assert event["tool_identifier"] == "get_me"
        assert event["decision"] == "allow"
        assert event["fingerprint_status"] == "approved"
        assert event["response_inspection_outcome"] == "clean"
        assert event["upstream_executed"] is True
        assert event["sanitized_arguments"] == {}
        assert event["risk_score"] == 10
        assert event["risk_category"] == "Low"
        assert event["risk_factors"] == ["read_only_operation"]

        detail = client.get(f"/api/events/{event['id']}")
        assert detail.status_code == 200
        assert detail.json() == event
        assert client.get("/api/events/99999").status_code == 404

        summary = client.get("/api/summary").json()
        assert summary == {
            "total_events": 1,
            "allowed": 1,
            "denied": 0,
            "upstream_executed": 1,
            "active_connections": 0,
        }
        connections = client.get("/api/connections").json()
        assert len(connections) >= 1
        github_conn = next(c for c in connections if c["server_identifier"] == "github-mcp-server")
        assert github_conn["event_count"] == 1
        tool_ids = {tool["tool_identifier"] for tool in github_conn["tools"]}
        assert "get_me" in tool_ids
        assert "get_file_contents" in tool_ids
        assert all(tool["fingerprint_status"] == "approved" for tool in github_conn["tools"])

        policies = client.get("/api/policies")
        assert policies.status_code == 200
        assert policies.json()["authorization"]["default_effect"] == "deny"

        page = client.get("/")
        assert page.status_code == 200
        assert client.get("/styles.css").status_code == 200
        script = client.get("/app.js")
        assert script.status_code == 200
        assert "textContent" in script.text
        assert "innerHTML" not in script.text
