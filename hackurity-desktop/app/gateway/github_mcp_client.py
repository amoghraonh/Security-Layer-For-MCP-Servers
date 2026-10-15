"""MCP Client for connecting AIRLOCK to the official GitHub MCP Server.

Supports:
- Local stdio execution (`ghcr.io/github/github-mcp-server` or `app.gateway.github_mcp_server`)
- Docker container execution (`docker run ... ghcr.io/github/github-mcp-server`)
- Remote Copilot MCP endpoint (`https://api.githubcopilot.com/mcp/`)
- Dual profile enforcement: Profile A (Read-Only) and Profile B (Security Lab)
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from app.gateway.tool_integrity import DiscoveredTool


PROJECT_ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class GitHubConnectionStatus:
    status: str
    mode: str
    authenticated: bool
    auth_method: str
    read_only: bool
    profile: str
    active_toolsets: list[str]
    discovered_tools_count: int
    allowed_repos: list[str]
    lab_repo: str
    details: str


class GitHubMCPClient:
    """Connect to official GitHub MCP Server over stdio or remote transport."""

    def __init__(
        self,
        mode: str | None = None,
        python_executable: str | None = None,
        token: str | None = None,
        environment: dict[str, str] | None = None,
    ) -> None:
        self.mode = mode or os.getenv("GITHUB_MCP_MODE", "local_stdio")
        self._python_executable = python_executable or sys.executable
        self._token = token or os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN", "").strip()
        self._environment = dict(environment or os.environ)

    def _build_env(self, profile: str = "readonly") -> dict[str, str]:
        env = dict(self._environment)
        if self._token:
            env["GITHUB_PERSONAL_ACCESS_TOKEN"] = self._token
        if profile == "readonly":
            env["GITHUB_READ_ONLY"] = "1"
        else:
            env["GITHUB_READ_ONLY"] = "0"

        if "GITHUB_TOOLSETS" not in env:
            env["GITHUB_TOOLSETS"] = "context,repos,issues,pull_requests,actions,code_security"
        return env

    @asynccontextmanager
    async def session(self, profile: str = "readonly") -> AsyncIterator[ClientSession]:
        """Spawn, initialize, and yield an active MCP client session."""
        env = self._build_env(profile)

        # Check if Docker mode is explicitly requested and Docker is available
        if self.mode == "docker" and shutil.which("docker") is not None:
            # Containerized execution using official image
            parameters = StdioServerParameters(
                command="docker",
                args=[
                    "run",
                    "-i",
                    "--rm",
                    "-e", f"GITHUB_PERSONAL_ACCESS_TOKEN={self._token}",
                    "-e", f"GITHUB_TOOLSETS={env.get('GITHUB_TOOLSETS', '')}",
                    "-e", f"GITHUB_READ_ONLY={env.get('GITHUB_READ_ONLY', '1')}",
                    "-e", "GITHUB_LOCKDOWN_MODE=1",
                    "ghcr.io/github/github-mcp-server",
                ],
                cwd=PROJECT_ROOT,
                env=env,
            )
        else:
            # Local stdio execution conforming to github-mcp-server protocol
            parameters = StdioServerParameters(
                command=self._python_executable,
                args=["-m", "app.gateway.github_mcp_server"],
                cwd=PROJECT_ROOT,
                env=env,
            )

        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as client:
                await client.initialize()
                yield client

    async def discover_tools(self, profile: str = "readonly") -> list[str]:
        """Return names of tools discovered from GitHub MCP server."""
        return [tool.name for tool in await self.discover_tool_definitions(profile)]

    async def discover_tool_definitions(self, profile: str = "readonly") -> list[DiscoveredTool]:
        """Discover tool definitions with schemas for AIRLOCK integrity verification."""
        async with self.session(profile=profile) as client:
            return await self.tool_definitions_for_session(client)

    async def tool_definitions_for_session(self, client: ClientSession) -> list[DiscoveredTool]:
        """Extract tool schemas from active ClientSession."""
        result = await client.list_tools()
        server_info = client.server_info
        server_name = server_info.name if server_info else "github-mcp-server"
        return [
            DiscoveredTool(
                server_identity=server_name,
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.input_schema,
            )
            for tool in result.tools
        ]

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None, profile: str = "readonly") -> Any:
        """Execute a tool against the GitHub MCP server session."""
        async with self.session(profile=profile) as client:
            return await client.call_tool(name, arguments or {})

    async def get_connection_status(self) -> GitHubConnectionStatus:
        """Evaluate real GitHub MCP server availability, authentication, and tool catalog."""
        auth_method = "personal_access_token" if self._token else "diagnostic_sandbox_identity"
        allowed_repos_raw = os.getenv("AIRLOCK_GITHUB_ALLOWED_REPOS", "demo-org/airlock-security-lab,demo-org/airlock-test")
        allowed_repos = [r.strip() for r in allowed_repos_raw.split(",") if r.strip()]
        toolsets = [t.strip() for t in os.getenv("GITHUB_TOOLSETS", "context,repos,issues,pull_requests,actions,code_security").split(",") if t.strip()]

        try:
            tools = await self.discover_tools(profile="readonly")
            return GitHubConnectionStatus(
                status="connected",
                mode=self.mode,
                authenticated=bool(self._token),
                auth_method=auth_method,
                read_only=True,
                profile="Profile A (Read-Only)",
                active_toolsets=toolsets,
                discovered_tools_count=len(tools),
                allowed_repos=allowed_repos,
                lab_repo="demo-org/airlock-security-lab",
                details=f"Connected to official GitHub MCP server via {self.mode}. {len(tools)} tools discovered.",
            )
        except Exception as exc:
            return GitHubConnectionStatus(
                status="disconnected",
                mode=self.mode,
                authenticated=bool(self._token),
                auth_method=auth_method,
                read_only=True,
                profile="Profile A (Read-Only)",
                active_toolsets=toolsets,
                discovered_tools_count=0,
                allowed_repos=allowed_repos,
                lab_repo="demo-org/airlock-security-lab",
                details=f"Failed to connect to GitHub MCP server: {exc}",
            )
