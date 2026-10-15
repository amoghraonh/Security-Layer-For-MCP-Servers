"""Downstream test client for exercising AIRLOCK through MCP stdio."""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from app.gateway.mcp_client import PROJECT_ROOT


class GatewayMCPClient:
    """Start AIRLOCK as a downstream MCP server and communicate over stdio."""

    def __init__(self, environment: dict[str, str] | None = None) -> None:
        self._environment = environment

    @asynccontextmanager
    async def session(self) -> AsyncIterator[ClientSession]:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "app.gateway.gateway_server"],
            cwd=PROJECT_ROOT,
            env=dict(os.environ | (self._environment or {})),
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                yield client
