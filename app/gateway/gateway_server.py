"""AIRLOCK: an MCP server downstream and MCP client upstream for GitHub MCP."""

from __future__ import annotations

import anyio
import json
import os
from pathlib import Path
from typing import Any

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
UPSTREAM_SERVER_ID = "github-mcp-server"


async def create_gateway_server() -> MCPServer:
    """Discover upstream GitHub tools, then expose only names permitted by local policy."""
    policy = JsonPolicy.from_file(POLICY_PATH)
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
            err_msg = result.content[0].text if result.content else "Upstream error"
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
            raise ToolError(err_msg)

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

        return json.dumps(
            {
                "airlock_response_inspection": {
                    "action": "flag",
                    "matches": inspection.matches,
                },
                "sentry_x_response_inspection": {
                    "action": "flag",
                    "matches": inspection.matches,
                },
                "upstream_response": response_text,
            },
            sort_keys=True,
        )

    # ================= REGISTRATION OF GITHUB MCP TOOLS =================
    if "get_me" in approved_names:
        @server.tool(name="get_me", description="Get information about the authenticated GitHub user and environment.")
        async def get_me() -> str:
            return await forward("get_me", {})

    if "search_repositories" in approved_names:
        @server.tool(name="search_repositories", description="Search for GitHub repositories via query string.")
        async def search_repositories(query: str, per_page: int = 10, page: int = 1) -> str:
            return await forward("search_repositories", {"query": query, "per_page": per_page, "page": page})

    if "get_file_contents" in approved_names:
        @server.tool(name="get_file_contents", description="Get contents of a file or directory in a repository.")
        async def get_file_contents(owner: str, repo: str, path: str, ref: str = "main") -> str:
            return await forward("get_file_contents", {"owner": owner, "repo": repo, "path": path, "ref": ref})

    if "list_commits" in approved_names:
        @server.tool(name="list_commits", description="List commits on a branch or repository.")
        async def list_commits(owner: str, repo: str, sha: str = "main", per_page: int = 10) -> str:
            return await forward("list_commits", {"owner": owner, "repo": repo, "sha": sha, "per_page": per_page})

    if "get_commit" in approved_names:
        @server.tool(name="get_commit", description="Get details of a specific commit by SHA.")
        async def get_commit(owner: str, repo: str, sha: str) -> str:
            return await forward("get_commit", {"owner": owner, "repo": repo, "sha": sha})

    if "list_branches" in approved_names:
        @server.tool(name="list_branches", description="List branches for a specified repository.")
        async def list_branches(owner: str, repo: str, protected: bool | None = None) -> str:
            args: dict[str, Any] = {"owner": owner, "repo": repo}
            if protected is not None:
                args["protected"] = protected
            return await forward("list_branches", args)

    if "list_tags" in approved_names:
        @server.tool(name="list_tags", description="List tags for a specified repository.")
        async def list_tags(owner: str, repo: str) -> str:
            return await forward("list_tags", {"owner": owner, "repo": repo})

    if "list_issues" in approved_names:
        @server.tool(name="list_issues", description="List issues in a repository.")
        async def list_issues(owner: str, repo: str, state: str = "open", per_page: int = 10) -> str:
            return await forward("list_issues", {"owner": owner, "repo": repo, "state": state, "per_page": per_page})

    if "search_issues" in approved_names:
        @server.tool(name="search_issues", description="Search issues across repositories.")
        async def search_issues(query: str, per_page: int = 10) -> str:
            return await forward("search_issues", {"query": query, "per_page": per_page})

    if "issue_read" in approved_names:
        @server.tool(name="issue_read", description="Read a specific issue by issue number.")
        async def issue_read(owner: str, repo: str, issue_number: int) -> str:
            return await forward("issue_read", {"owner": owner, "repo": repo, "issue_number": issue_number})

    if "list_pull_requests" in approved_names:
        @server.tool(name="list_pull_requests", description="List pull requests in a repository.")
        async def list_pull_requests(owner: str, repo: str, state: str = "open", per_page: int = 10) -> str:
            return await forward("list_pull_requests", {"owner": owner, "repo": repo, "state": state, "per_page": per_page})

    if "pull_request_read" in approved_names:
        @server.tool(name="pull_request_read", description="Read a specific pull request by pull request number.")
        async def pull_request_read(owner: str, repo: str, pull_number: int) -> str:
            return await forward("pull_request_read", {"owner": owner, "repo": repo, "pull_number": pull_number})

    if "list_workflows" in approved_names:
        @server.tool(name="list_workflows", description="List GitHub Actions workflows for a repository.")
        async def list_workflows(owner: str, repo: str) -> str:
            return await forward("list_workflows", {"owner": owner, "repo": repo})

    if "list_workflow_runs" in approved_names:
        @server.tool(name="list_workflow_runs", description="List recent workflow runs for a repository.")
        async def list_workflow_runs(owner: str, repo: str, per_page: int = 10) -> str:
            return await forward("list_workflow_runs", {"owner": owner, "repo": repo, "per_page": per_page})

    if "list_dependabot_alerts" in approved_names:
        @server.tool(name="list_dependabot_alerts", description="List open Dependabot alerts for a repository.")
        async def list_dependabot_alerts(owner: str, repo: str) -> str:
            return await forward("list_dependabot_alerts", {"owner": owner, "repo": repo})

    if "list_code_scanning_alerts" in approved_names:
        @server.tool(name="list_code_scanning_alerts", description="List code scanning alerts for a repository.")
        async def list_code_scanning_alerts(owner: str, repo: str) -> str:
            return await forward("list_code_scanning_alerts", {"owner": owner, "repo": repo})

    # Write tools (exposed in Security Lab / controlled profile)
    if "create_or_update_file" in approved_names:
        @server.tool(name="create_or_update_file", description="Create or update a file in a repository.")
        async def create_or_update_file(
            owner: str, repo: str, path: str, message: str, content: str, branch: str = "feature/update", sha: str | None = None
        ) -> str:
            args = {"owner": owner, "repo": repo, "path": path, "message": message, "content": content, "branch": branch}
            if sha:
                args["sha"] = sha
            return await forward("create_or_update_file", args)

    if "create_branch" in approved_names:
        @server.tool(name="create_branch", description="Create a new branch in a repository.")
        async def create_branch(owner: str, repo: str, branch: str, from_branch: str = "main") -> str:
            return await forward("create_branch", {"owner": owner, "repo": repo, "branch": branch, "from_branch": from_branch})

    if "delete_file" in approved_names:
        @server.tool(name="delete_file", description="Delete a file from a repository.")
        async def delete_file(owner: str, repo: str, path: str, message: str, sha: str, branch: str = "feature/update") -> str:
            return await forward("delete_file", {"owner": owner, "repo": repo, "path": path, "message": message, "sha": sha, "branch": branch})

    if "delete_repository" in approved_names:
        @server.tool(name="delete_repository", description="Delete a repository.")
        async def delete_repository(owner: str, repo: str) -> str:
            return await forward("delete_repository", {"owner": owner, "repo": repo})

    if "issue_write" in approved_names:
        @server.tool(name="issue_write", description="Create a new issue in a repository.")
        async def issue_write(owner: str, repo: str, title: str, body: str, labels: list[str] | None = None) -> str:
            return await forward("issue_write", {"owner": owner, "repo": repo, "title": title, "body": body, "labels": labels or []})

    if "add_issue_comment" in approved_names:
        @server.tool(name="add_issue_comment", description="Add a comment to an existing issue.")
        async def add_issue_comment(owner: str, repo: str, issue_number: int, body: str) -> str:
            return await forward("add_issue_comment", {"owner": owner, "repo": repo, "issue_number": issue_number, "body": body})

    if "create_pull_request" in approved_names:
        @server.tool(name="create_pull_request", description="Create a new pull request.")
        async def create_pull_request(owner: str, repo: str, title: str, head: str, base: str = "main", body: str = "") -> str:
            return await forward("create_pull_request", {"owner": owner, "repo": repo, "title": title, "head": head, "base": base, "body": body})

    if "merge_pull_request" in approved_names:
        @server.tool(name="merge_pull_request", description="Merge an approved pull request.")
        async def merge_pull_request(owner: str, repo: str, pull_number: int, commit_title: str | None = None) -> str:
            return await forward("merge_pull_request", {"owner": owner, "repo": repo, "pull_number": pull_number, "commit_title": commit_title})

    return server


async def run_gateway() -> None:
    server = await create_gateway_server()
    await server.run_stdio_async()


def main() -> None:
    anyio.run(run_gateway)


if __name__ == "__main__":
    main()
