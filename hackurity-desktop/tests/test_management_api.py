"""SQLite audit and read-only management API integration tests."""

from __future__ import annotations

from pathlib import Path

import anyio
from fastapi.testclient import TestClient

from app.api.management import create_management_app
from app.audit.sqlite_audit import SQLiteAuditLog, sanitize_arguments
from app.gateway.gateway_client import GatewayMCPClient


def test_argument_sanitization_and_sqlite_round_trip(tmp_path: Path) -> None:
    audit = SQLiteAuditLog(tmp_path / "audit.db")
    event_id = audit.record_event(
        server_identifier="test-server",
        tool_identifier="test-tool",
        arguments={"token": "do-not-store", "nested": {"password": "nope"}, "safe": "value"},
        decision="deny",
        matched_policy="test",
        reason="test reason",
        fingerprint_status="not_checked",
        response_inspection_outcome="not_applicable",
        upstream_executed=False,
    )
    event = audit.event(event_id)
    assert event is not None
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
            result = await session.call_tool("list_resources")
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
        assert event["tool_identifier"] == "list_resources"
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
        assert client.get("/api/connections").json()[0]["event_count"] == 1
        connection = client.get("/api/connections").json()[0]
        assert {tool["tool_identifier"] for tool in connection["tools"]} == {
            "delete_resource",
            "list_resources",
            "restart_vm",
            "list_local_repository_files",
            "read_local_repository_file",
            "list_synthetic_azure_resources",
            "get_synthetic_azure_resource",
        }
        assert all(tool["fingerprint_status"] == "approved" for tool in connection["tools"])

        policies = client.get("/api/policies")
        assert policies.status_code == 200
        assert policies.json()["authorization"]["default_effect"] == "deny"

        page = client.get("/")
        assert page.status_code == 200
        assert "Security Console" in page.text
        assert client.get("/styles.css").status_code == 200
        script = client.get("/app.js")
        assert script.status_code == 200
        assert "textContent" in script.text
        assert "innerHTML" not in script.text
