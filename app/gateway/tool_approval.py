"""Explicit local administrator command for approving discovered MCP tools."""

from __future__ import annotations

import argparse
import anyio
from pathlib import Path

from app.gateway.mcp_client import LocalMCPClient, PROJECT_ROOT
from app.gateway.tool_integrity import write_approvals


DEFAULT_APPROVALS_PATH = PROJECT_ROOT / "config" / "tool_approvals.json"


async def approve_discovered_tools(path: Path, environment: dict[str, str] | None = None) -> None:
    """Discover current definitions and intentionally replace the approval registry."""
    tools = await LocalMCPClient(environment=environment).discover_tool_definitions()
    write_approvals(path, tools)


def main() -> None:
    parser = argparse.ArgumentParser(description="Approve current local MCP tool definitions.")
    parser.add_argument("action", choices=["approve"])
    parser.add_argument("--all-discovered", action="store_true", help="Required acknowledgement to replace approvals")
    parser.add_argument("--config", type=Path, default=DEFAULT_APPROVALS_PATH)
    arguments = parser.parse_args()
    if not arguments.all_discovered:
        parser.error("--all-discovered is required; review tool definitions before approving them")
    anyio.run(approve_discovered_tools, arguments.config)
    print(f"Approved current discovered tools in {arguments.config}")


if __name__ == "__main__":
    main()
