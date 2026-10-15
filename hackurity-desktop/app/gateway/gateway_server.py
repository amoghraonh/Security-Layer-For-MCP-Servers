"""AIRLOCK: an MCP server downstream and MCP client upstream."""

from __future__ import annotations

import anyio
import json
import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from app.audit.sqlite_audit import SQLiteAuditLog
from app.gateway.mcp_client import LocalMCPClient, PROJECT_ROOT
from app.gateway.tool_integrity import ApprovalRegistry
from app.gateway.response_inspection import ResponseInspector
from app.policies.json_policy import JsonPolicy
from app.security.risk import assess_tool_request


TRUSTED_IDENTITY = "local-development-agent"
POLICY_PATH = PROJECT_ROOT / "config" / "policy.json"
DEFAULT_APPROVALS_PATH = PROJECT_ROOT / "config" / "tool_approvals.json"
DEFAULT_RESPONSE_INSPECTION_PATH = PROJECT_ROOT / "config" / "response_inspection.json"
DEFAULT_AUDIT_PATH = PROJECT_ROOT / "data" / "sentry_x_audit.db"
# Stable internal identifier retained so pre-existing tool fingerprints remain valid.
UPSTREAM_SERVER_ID = "sentry-x-synthetic-upstream"


async def create_gateway_server() -> MCPServer:
    """Discover upstream tools, then expose only names permitted by local policy."""
    policy = JsonPolicy.from_file(POLICY_PATH)
    # Explicitly pass server process configuration; stdio clients sanitize inherited env.
    upstream_client = LocalMCPClient(environment=dict(os.environ))
    approvals_path = Path(os.environ.get("SENTRY_X_APPROVALS_FILE", DEFAULT_APPROVALS_PATH))
    approval_registry = ApprovalRegistry.from_file(approvals_path)
    inspection_path = Path(os.environ.get("SENTRY_X_RESPONSE_INSPECTION_FILE", DEFAULT_RESPONSE_INSPECTION_PATH))
    response_inspector = ResponseInspector.from_file(inspection_path)
    audit_path = Path(os.environ.get("SENTRY_X_AUDIT_DATABASE", DEFAULT_AUDIT_PATH))
    audit_log = SQLiteAuditLog(audit_path)
    discovered_tools = await upstream_client.discover_tool_definitions()
    verified_tools = {tool.name for tool in discovered_tools if approval_registry.is_approved(tool)}
    approved_names = policy.approved_tool_names(TRUSTED_IDENTITY) & verified_tools
    server = MCPServer(name="airlock-gateway", version="0.1.0")

    async def forward(tool_name: str, arguments: dict[str, object]) -> str:
        # Security boundary: policy runs before an upstream connection is opened.
        risk = assess_tool_request(tool_name, arguments)
        decision = policy.authorize(TRUSTED_IDENTITY, tool_name, arguments)
        if not decision.allowed:
            audit_log.record_event(
                server_identifier=UPSTREAM_SERVER_ID,
                tool_identifier=tool_name,
                arguments=arguments,
                decision="deny",
                matched_policy="authorization",
                reason=decision.reason,
                fingerprint_status="not_checked",
                response_inspection_outcome="not_applicable",
                upstream_executed=False,
                risk_score=risk.score,
                risk_category=risk.category,
                risk_factors=risk.factors,
            )
            raise ToolError(f"Blocked by AIRLOCK policy: {decision.reason}")
        async with upstream_client.session() as upstream_session:
            definitions = await upstream_client.tool_definitions_for_session(upstream_session)
            definition = next((item for item in definitions if item.name == tool_name), None)
            if definition is None or not approval_registry.is_approved(definition):
                audit_log.record_event(
                    server_identifier=UPSTREAM_SERVER_ID,
                    tool_identifier=tool_name,
                    arguments=arguments,
                    decision="deny",
                    matched_policy="tool_integrity",
                    reason="Unapproved or modified tool definition",
                    fingerprint_status="mismatch",
                    response_inspection_outcome="not_applicable",
                    upstream_executed=False,
                    risk_score=risk.score,
                    risk_category=risk.category,
                    risk_factors=risk.factors,
                )
                raise ToolError(f"Blocked by AIRLOCK integrity check: unapproved or modified tool: {tool_name}")
            result = await upstream_session.call_tool(tool_name, arguments)
        if result.is_error:
            audit_log.record_event(
                server_identifier=UPSTREAM_SERVER_ID,
                tool_identifier=tool_name,
                arguments=arguments,
                decision="allow",
                matched_policy="authorization",
                reason=decision.reason,
                fingerprint_status="approved",
                response_inspection_outcome="upstream_error",
                upstream_executed=True,
                risk_score=risk.score,
                risk_category=risk.category,
                risk_factors=risk.factors,
            )
            raise ToolError(result.content[0].text)
        response_text = "".join(
            content.text for content in result.content if hasattr(content, "text")
        )
        inspection = response_inspector.inspect(response_text)
        inspection_outcome = "clean" if not inspection.suspicious else (
            f"{response_inspector.action}:" + ",".join(inspection.matches)
        )
        audit_log.record_event(
            server_identifier=UPSTREAM_SERVER_ID,
            tool_identifier=tool_name,
            arguments=arguments,
            decision="allow",
            matched_policy="authorization",
            reason=decision.reason,
            fingerprint_status="approved",
            response_inspection_outcome=inspection_outcome,
            upstream_executed=True,
            risk_score=risk.score,
            risk_category=risk.category,
            risk_factors=risk.factors,
        )
        if not inspection.suspicious or response_inspector.action == "allow":
            return response_text
        if response_inspector.action == "quarantine":
            raise ToolError(
                "Response quarantined by AIRLOCK inspection: " + ", ".join(inspection.matches)
            )
        # Flag keeps the original response intact inside a documented envelope.
        return json.dumps(
            {
                "sentry_x_response_inspection": {
                    "action": "flag",
                    "matches": inspection.matches,
                },
                "upstream_response": response_text,
            },
            sort_keys=True,
        )

    if "list_resources" in approved_names:
        @server.tool(description="List resources permitted by the AIRLOCK policy.")
        async def list_resources() -> str:
            return await forward("list_resources", {})

    if "restart_vm" in approved_names:
        @server.tool(description="Restart an explicitly permitted synthetic development VM.")
        async def restart_vm(resource_name: str) -> str:
            return await forward("restart_vm", {"resource_name": resource_name})

    if "list_local_repository_files" in approved_names:
        @server.tool(description="List files in the policy-approved harmless local Git fixture.")
        async def list_local_repository_files() -> str:
            return await forward("list_local_repository_files", {})

    if "read_local_repository_file" in approved_names:
        @server.tool(description="Read one policy-approved text file from the harmless local Git fixture.")
        async def read_local_repository_file(relative_path: str) -> str:
            return await forward("read_local_repository_file", {"relative_path": relative_path})

    if "list_synthetic_azure_resources" in approved_names:
        @server.tool(description="List policy-approved fictional Azure-style local resource metadata.")
        async def list_synthetic_azure_resources() -> str:
            return await forward("list_synthetic_azure_resources", {})

    if "get_synthetic_azure_resource" in approved_names:
        @server.tool(description="Read one policy-approved fictional Azure-style local resource.")
        async def get_synthetic_azure_resource(resource_name: str) -> str:
            return await forward("get_synthetic_azure_resource", {"resource_name": resource_name})

    return server


async def run_gateway() -> None:
    server = await create_gateway_server()
    await server.run_stdio_async()


def main() -> None:
    anyio.run(run_gateway)


if __name__ == "__main__":
    main()
