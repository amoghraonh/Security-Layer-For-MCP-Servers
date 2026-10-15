"""A small MCP v2 stdio client for AIRLOCK's safe local upstream server."""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from app.gateway.tool_integrity import DiscoveredTool


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class LocalMCPClient:
    """Connect to the local synthetic server using the real MCP stdio transport."""

    def __init__(
        self, python_executable: str | None = None, environment: dict[str, str] | None = None
    ) -> None:
        self._python_executable = python_executable or sys.executable
        self._environment = environment

    @asynccontextmanager
    async def session(self) -> AsyncIterator[ClientSession]:
        """Spawn, initialize, and close one upstream MCP client session."""
        parameters = StdioServerParameters(
            command=self._python_executable,
            args=["-m", "mcp_servers.local_server"],
            cwd=PROJECT_ROOT,
            env=self._environment,
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                yield client

    async def discover_tools(self) -> list[str]:
        """Perform MCP ``tools/list`` and return the discovered tool names."""
        return [tool.name for tool in await self.discover_tool_definitions()]

    async def discover_tool_definitions(self) -> list[DiscoveredTool]:
        """Perform MCP ``tools/list`` and retain metadata used for verification."""
        async with self.session() as client:
            return await self.tool_definitions_for_session(client)

    async def tool_definitions_for_session(self, client: ClientSession) -> list[DiscoveredTool]:
        """Read the discovered tool metadata for an initialized MCP session."""
        result = await client.list_tools()
        server_info = client.server_info
        if server_info is None:
            raise RuntimeError("Upstream MCP server did not provide an identity")
        return [
            DiscoveredTool(
                server_identity=server_info.name,
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.input_schema,
            )
            for tool in result.tools
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Perform MCP ``tools/call`` against one fresh local server session."""
        async with self.session() as client:
            return await client.call_tool(name, arguments or {})
