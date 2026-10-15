"""Integration tests using a real stdio MCP subprocess, not a REST substitute."""

from __future__ import annotations

import json

import anyio

from app.gateway.mcp_client import LocalMCPClient


def _result_json(result: object) -> object:
    content = getattr(result, "content")
    return json.loads(content[0].text)


def test_tools_list_discovers_the_synthetic_tools() -> None:
    async def scenario() -> None:
        tool_names = await LocalMCPClient().discover_tools()
        assert set(tool_names) == {
            "list_resources",
            "restart_vm",
            "delete_resource",
            "list_local_repository_files",
            "read_local_repository_file",
            "list_synthetic_azure_resources",
            "get_synthetic_azure_resource",
        }

    anyio.run(scenario)


def test_read_only_local_repository_and_fictional_azure_data() -> None:
    async def scenario() -> None:
        client = LocalMCPClient()
        async with client.session() as session:
            files = await session.call_tool("list_local_repository_files")
            assert files.is_error is False
            paths = _result_json(files)
            assert isinstance(paths, list)
            assert paths

            text_file = next(path for path in paths if path.endswith(".gitignore"))
            read_file = await session.call_tool("read_local_repository_file", {"relative_path": text_file})
            assert read_file.is_error is False
            assert read_file.content[0].text

            resources = await session.call_tool("list_synthetic_azure_resources")
            assert resources.is_error is False
            inventory = _result_json(resources)
            assert {item["name"] for item in inventory} == {
                "sx-demo-web-01",
                "sxdemoartifactstore",
                "sx-demo-vault",
            }
            assert all(item["tags"]["data_classification"] == "fictional" for item in inventory)

            one_resource = await session.call_tool(
                "get_synthetic_azure_resource", {"resource_name": "sx-demo-web-01"}
            )
            assert one_resource.is_error is False
            assert _result_json(one_resource)["location"] == "eastus2"

    anyio.run(scenario)


def test_tools_call_restarts_and_deletes_only_synthetic_resources() -> None:
    async def scenario() -> None:
        client = LocalMCPClient()
        async with client.session() as session:
            initial = await session.call_tool("list_resources")
            assert initial.is_error is False
            assert len(_result_json(initial)) == 3

            restarted = await session.call_tool("restart_vm", {"resource_name": "dev-vm-01"})
            assert restarted.is_error is False
            assert _result_json(restarted)["status"] == "restarted"

            deleted = await session.call_tool("delete_resource", {"resource_name": "cache-demo-01"})
            assert deleted.is_error is False
            assert _result_json(deleted)["deleted"] == "true"

            remaining = await session.call_tool("list_resources")
            assert [item["name"] for item in _result_json(remaining)] == [
                "database-demo-01",
                "dev-vm-01",
            ]

    anyio.run(scenario)


def test_unknown_resource_and_unknown_tool_return_mcp_tool_errors() -> None:
    async def scenario() -> None:
        client = LocalMCPClient()
        async with client.session() as session:
            missing_resource = await session.call_tool("restart_vm", {"resource_name": "vm-does-not-exist"})
            assert missing_resource.is_error is True
            assert "Unknown synthetic resource" in missing_resource.content[0].text

            missing_tool = await session.call_tool("not_a_tool", {})
            assert missing_tool.is_error is True
            assert "Unknown tool" in missing_tool.content[0].text

    anyio.run(scenario)
