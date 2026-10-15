"""Reliability boundaries: invalid API input and fail-closed policy decisions."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.api.management import create_management_app
from app.audit.sqlite_audit import SQLiteAuditLog
from app.policies.json_policy import JsonPolicy


def test_management_api_rejects_invalid_event_limits_and_missing_event(tmp_path: Path) -> None:
    app = create_management_app(tmp_path / "audit.db")
    with TestClient(app) as client:
        assert client.get("/api/events?limit=0").status_code == 422
        assert client.get("/api/events?limit=501").status_code == 422
        assert client.get("/api/events/1").status_code == 404


def test_policy_fails_closed_for_unknown_identity_tool_and_arguments() -> None:
    policy = JsonPolicy.from_file(Path("config/policy.json"))
    assert policy.authorize("untrusted-agent", "list_resources", {}).allowed is False
    assert policy.authorize("local-development-agent", "delete_resource", {"resource_name": "cache-demo-01"}).allowed is False
    assert policy.authorize("local-development-agent", "restart_vm", {"resource_name": "dev-vm-01", "extra": "x"}).allowed is False


def test_audit_database_handles_empty_state_without_inventing_events(tmp_path: Path) -> None:
    audit = SQLiteAuditLog(tmp_path / "empty.db")
    assert audit.events() == []
    assert audit.summary() == {"total_events": 0, "allowed": 0, "denied": 0, "upstream_executed": 0}
    assert audit.connections() == []
