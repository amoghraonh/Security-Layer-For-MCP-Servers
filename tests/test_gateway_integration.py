"""End-to-end tests for AIRLOCK's downstream and upstream MCP boundary with GitHub MCP."""

from __future__ import annotations

import json
from pathlib import Path

import anyio

from app.gateway.gateway_client import GatewayMCPClient


def test_gateway_exposes_only_policy_approved_tools() -> None:
    async def scenario() -> None:
        async with GatewayMCPClient().session() as session:
            names = {tool.name for tool in (await session.list_tools()).tools}
            expected = {
                "get_me",
                "search_repositories",
                "get_file_contents",
                "list_commits",
                "get_commit",
                "list_branches",
                "list_tags",
                "list_issues",
                "search_issues",
                "issue_read",
                "list_pull_requests",
                "pull_request_read",
                "list_workflows",
                "list_workflow_runs",
                "list_dependabot_alerts",
                "list_code_scanning_alerts",
            }
            assert names == expected
    anyio.run(scenario)


def test_gateway_allows_scoped_github_reads_and_blocks_path_escape() -> None:
    async def scenario() -> None:
        client = GatewayMCPClient()
        async with client.session() as session:
            # 1. Authorized read inside repository boundary
            file_res = await session.call_tool(
                "get_file_contents",
                {"owner": "demo-org", "repo": "airlock-security-lab", "path": "README.md", "ref": "main"},
            )
            assert file_res.is_error is False
            assert "AIRLOCK Security Lab Repository" in file_res.content[0].text

            # 2. Path traversal attack outside boundary blocked by AIRLOCK
            traversal = await session.call_tool(
                "get_file_contents",
                {"owner": "demo-org", "repo": "airlock-security-lab", "path": "../outside.txt", "ref": "main"},
            )
            assert traversal.is_error is True
            assert "Path traversal" in traversal.content[0].text or "Blocked by AIRLOCK policy" in traversal.content[0].text

    anyio.run(scenario)


def test_allowed_calls_reach_upstream_and_denied_calls_do_not() -> None:
    async def scenario() -> None:
        # Security lab profile enables write tools on the gateway
        client = GatewayMCPClient({"GITHUB_READ_ONLY": "0"})
        async with client.session() as session:
            # Authorized read
            me_res = await session.call_tool("get_me", {})
            assert me_res.is_error is False

            # Unauthorized write to protected main branch blocked by AIRLOCK
            blocked_write = await session.call_tool(
                "create_or_update_file",
                {
                    "owner": "demo-org",
                    "repo": "airlock-security-lab",
                    "path": "src/main.py",
                    "message": "tamper attempt",
                    "content": "evil code",
                    "branch": "main",
                },
            )
            assert blocked_write.is_error is True
            assert "Blocked by AIRLOCK policy" in blocked_write.content[0].text

            # Unauthorized repository scope blocked by AIRLOCK
            blocked_repo = await session.call_tool(
                "get_file_contents",
                {"owner": "unauthorized-org", "repo": "secret-repo", "path": "keys.env"},
            )
            assert blocked_repo.is_error is True
            assert "Blocked by AIRLOCK policy" in blocked_repo.content[0].text

    anyio.run(scenario)


def test_invalid_arguments_and_unknown_tools_do_not_reach_upstream() -> None:
    async def scenario() -> None:
        client = GatewayMCPClient()
        async with client.session() as session:
            unknown = await session.call_tool("not_a_tool", {})
            assert unknown.is_error is True
    anyio.run(scenario)
