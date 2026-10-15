"""Gemini controller tests using a fake provider and real AIRLOCK MCP gateway."""

from __future__ import annotations

from pathlib import Path

import anyio
from fastapi.testclient import TestClient
from google.genai import types

from app.agent.controller import GeminiMcpController
from app.agent.gemini_provider import GeminiFunctionCall, GeminiProvider, GeminiReply
from app.agent.mcp_gateway_bridge import MCPGatewayBridge
from app.api.management import create_management_app
from app.audit.sqlite_audit import SQLiteAuditLog
from app.gateway.gateway_client import GatewayMCPClient


class ScriptedProvider:
    """A deterministic Gemini stand-in that never creates a fake gateway result."""

    def __init__(self, calls: list[GeminiFunctionCall]) -> None:
        self._calls = calls
        self.requests: list[tuple[list[object], list[types.Tool]]] = []

    async def generate(self, contents: list[object], tools: list[types.Tool]) -> GeminiReply:
        self.requests.append((contents, tools))
        if len(self.requests) == 1:
            return GeminiReply(
                text="",
                function_calls=self._calls,
                raw_content=types.Content(role="model", parts=[]),
            )
        return GeminiReply(
            text="I used the AIRLOCK gateway result above.",
            function_calls=[],
            raw_content=types.Content(role="model", parts=[]),
        )

    tool_response_content = staticmethod(GeminiProvider.tool_response_content)


def test_gemini_requested_allowed_tool_runs_through_real_gateway(tmp_path: Path) -> None:
    counter_file = tmp_path / "upstream-counters.json"
    audit_database = tmp_path / "audit.db"
    provider = ScriptedProvider([GeminiFunctionCall("list_resources", {})])
    bridge = MCPGatewayBridge(
        lambda: GatewayMCPClient(
            {"SENTRY_X_COUNTER_FILE": str(counter_file), "SENTRY_X_AUDIT_DATABASE": str(audit_database)}
        )
    )

    result = anyio.run(GeminiMcpController(provider=provider, bridge=bridge).handle_message, "List my cloud resources")

    assert result.answer == "I used the AIRLOCK gateway result above."
    assert result.tool_results[0]["tool"] == "list_resources"
    assert result.tool_results[0]["status"] == "allowed"
    assert counter_file.read_text().find('"list_resources": 1') >= 0
    event = SQLiteAuditLog(audit_database).events()[0]
    assert event["tool_identifier"] == "list_resources"
    assert event["decision"] == "allow"
    assert event["upstream_executed"] is True
    declarations = provider.requests[0][1][0].function_declarations
    assert {declaration.name for declaration in declarations} == {
        "list_resources",
        "restart_vm",
        "list_local_repository_files",
        "read_local_repository_file",
        "list_synthetic_azure_resources",
        "get_synthetic_azure_resource",
    }


def test_gemini_requested_delete_is_blocked_by_gateway_before_upstream(tmp_path: Path) -> None:
    counter_file = tmp_path / "upstream-counters.json"
    provider = ScriptedProvider([GeminiFunctionCall("delete_resource", {"resource_name": "database-demo-01"})])
    bridge = MCPGatewayBridge(lambda: GatewayMCPClient({"SENTRY_X_COUNTER_FILE": str(counter_file)}))

    result = anyio.run(GeminiMcpController(provider=provider, bridge=bridge).handle_message, "Delete the production database")

    assert result.tool_results == [
        {
            "tool": "delete_resource",
            "status": "blocked",
            "message": result.tool_results[0]["message"],
        }
    ]
    assert counter_file.exists() is False


class EndpointController:
    async def handle_message(self, message: str):
        from app.agent.controller import ChatResult

        return ChatResult(answer=f"Received: {message}", tool_results=[])


def test_chat_endpoint_uses_injected_controller_and_validates_input(tmp_path: Path) -> None:
    app = create_management_app(tmp_path / "audit.db", chat_controller=EndpointController())
    with TestClient(app) as client:
        response = client.post("/api/chat", json={"message": "Hello AIRLOCK"})
        assert response.status_code == 200
        assert response.json() == {"answer": "Received: Hello AIRLOCK", "tool_results": []}
        assert client.post("/api/chat", json={"message": ""}).status_code == 422
