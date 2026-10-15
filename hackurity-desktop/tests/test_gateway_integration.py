"""End-to-end tests for AIRLOCK's downstream and upstream MCP boundary."""

from __future__ import annotations

import json
from pathlib import Path

import anyio

from app.gateway.gateway_client import GatewayMCPClient


def _counters(counter_file: Path) -> dict[str, int]:
    return json.loads(counter_file.read_text()) if counter_file.exists() else {}


def test_gateway_exposes_only_policy_approved_tools() -> None:
    async def scenario() -> None:
        async with GatewayMCPClient().session() as session:
            names = {tool.name for tool in (await session.list_tools()).tools}
            assert names == {
                "list_resources",
                "restart_vm",
                "list_local_repository_files",
                "read_local_repository_file",
                "list_synthetic_azure_resources",
                "get_synthetic_azure_resource",
            }
    anyio.run(scenario)


def test_gateway_allows_scoped_local_data_reads_and_blocks_path_escape(tmp_path: Path) -> None:
    counter_file = tmp_path / "upstream-counters.json"

    async def scenario() -> None:
        client = GatewayMCPClient({"SENTRY_X_COUNTER_FILE": str(counter_file)})
        async with client.session() as session:
            inventory = await session.call_tool("list_synthetic_azure_resources")
            assert inventory.is_error is False
            assert "sx-demo-web-01" in inventory.content[0].text

            repository_file = await session.call_tool(
                "read_local_repository_file", {"relative_path": "Global/Windows.gitignore"}
            )
            assert repository_file.is_error is False
            assert repository_file.content[0].text

            traversal = await session.call_tool(
                "read_local_repository_file", {"relative_path": "../outside.txt"}
            )
            assert traversal.is_error is True
            assert "path traversal" in traversal.content[0].text
            assert _counters(counter_file) == {
                "list_synthetic_azure_resources": 1,
                "read_local_repository_file": 1,
            }

    anyio.run(scenario)


def test_allowed_calls_reach_upstream_and_denied_calls_do_not(tmp_path: Path) -> None:
    counter_file = tmp_path / "upstream-counters.json"

    async def scenario() -> None:
        client = GatewayMCPClient({"SENTRY_X_COUNTER_FILE": str(counter_file)})
        async with client.session() as session:
            listed = await session.call_tool("list_resources")
            assert listed.is_error is False
            assert _counters(counter_file) == {"list_resources": 1}

            restarted = await session.call_tool("restart_vm", {"resource_name": "dev-vm-01"})
            assert restarted.is_error is False
            assert _counters(counter_file) == {"list_resources": 1, "restart_vm": 1}

            blocked_vm = await session.call_tool("restart_vm", {"resource_name": "vm-not-allowed"})
            assert blocked_vm.is_error is True
            assert "Blocked by AIRLOCK policy" in blocked_vm.content[0].text
            assert _counters(counter_file) == {"list_resources": 1, "restart_vm": 1}

            blocked_delete = await session.call_tool("delete_resource", {"resource_name": "cache-demo-01"})
            assert blocked_delete.is_error is True
            assert _counters(counter_file) == {"list_resources": 1, "restart_vm": 1}
    anyio.run(scenario)


def test_invalid_arguments_and_unknown_tools_do_not_reach_upstream(tmp_path: Path) -> None:
    counter_file = tmp_path / "upstream-counters.json"

    async def scenario() -> None:
        client = GatewayMCPClient({"SENTRY_X_COUNTER_FILE": str(counter_file)})
        async with client.session() as session:
            invalid = await session.call_tool("restart_vm", {"resource_name": 123})
            assert invalid.is_error is True
            unknown = await session.call_tool("not_a_tool", {})
            assert unknown.is_error is True
            assert _counters(counter_file) == {}
    anyio.run(scenario)
