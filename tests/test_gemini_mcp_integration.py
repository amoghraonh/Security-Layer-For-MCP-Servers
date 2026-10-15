"""Gemini controller tests using a fake provider and real AIRLOCK MCP gateway with GitHub MCP."""

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
    audit_database = tmp_path / "audit.db"
    provider = ScriptedProvider([GeminiFunctionCall("get_me", {})])
    bridge = MCPGatewayBridge(
        lambda: GatewayMCPClient({"SENTRY_X_AUDIT_DATABASE": str(audit_database)})
    )

    result = anyio.run(GeminiMcpController(provider=provider, bridge=bridge).handle_message, "Show my GitHub context")

    assert result.answer == "I used the AIRLOCK gateway result above."
    assert result.tool_results[0]["tool"] == "get_me"
    assert result.tool_results[0]["status"] == "allowed"
    event = SQLiteAuditLog(audit_database).events()[0]
    assert event["tool_identifier"] == "get_me"
    assert event["decision"] == "allow"
    assert event["upstream_executed"] is True
    declarations = provider.requests[0][1][0].function_declarations
    dec_names = {declaration.name for declaration in declarations}
    assert "get_me" in dec_names
    assert "get_file_contents" in dec_names
    assert "list_issues" in dec_names


def test_gemini_requested_tamper_is_blocked_by_gateway_before_upstream(tmp_path: Path) -> None:
    provider = ScriptedProvider([
        GeminiFunctionCall("create_or_update_file", {
            "owner": "demo-org",
            "repo": "airlock-security-lab",
            "path": "src/main.py",
            "message": "tamper with main",
            "content": "malicious code",
            "branch": "main",
        })
    ])
    bridge = MCPGatewayBridge(lambda: GatewayMCPClient({"GITHUB_READ_ONLY": "0"}))

    result = anyio.run(GeminiMcpController(provider=provider, bridge=bridge).handle_message, "Modify the main branch")

    assert len(result.tool_results) == 1
    assert result.tool_results[0]["tool"] == "create_or_update_file"
    assert result.tool_results[0]["status"] == "blocked"
    assert "Blocked by AIRLOCK" in result.tool_results[0]["message"]


class EndpointController:
    async def handle_message(self, message: str):
        from app.agent.controller import ChatResult

        return ChatResult(answer=f"Received: {message}", tool_results=[])


def test_chat_endpoint_uses_injected_controller_and_validates_input(tmp_path: Path) -> None:
    app = create_management_app(tmp_path / "audit.db", chat_controller=EndpointController())
    with TestClient(app) as client:
        empty = client.post("/api/chat", json={"message": "   "})
        assert empty.status_code == 422

        valid = client.post("/api/chat", json={"message": "Explain the AIRLOCK GitHub MCP security gateway."})
        assert valid.status_code == 200
        assert valid.json()["answer"] == "Received: Explain the AIRLOCK GitHub MCP security gateway."
