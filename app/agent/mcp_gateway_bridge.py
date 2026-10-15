"""Adapter that discovers and invokes tools only through AIRLOCK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from google.genai import types

from app.gateway.gateway_client import GatewayMCPClient


@dataclass(frozen=True)
class GatewayTool:
    """A downstream tool definition obtained from the AIRLOCK gateway."""

    name: str
    description: str
    input_schema: dict[str, Any]


class GatewayToolSession:
    """A single initialized downstream MCP session used for a model turn."""

    def __init__(self, client: Any, tools: list[GatewayTool]) -> None:
        self._client = client
        self.tools = tools
        self._tool_names = {tool.name for tool in tools}

    def gemini_tools(self) -> list[types.Tool]:
        """Translate already-authorized gateway metadata into Gemini declarations."""
        declarations = [
            types.FunctionDeclaration(
                name=tool.name,
                description=tool.description,
                parameters_json_schema=tool.input_schema,
            )
            for tool in self.tools
        ]
        return [types.Tool(function_declarations=declarations)] if declarations else []

    async def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Send every model-requested tool call to the gateway, never upstream directly."""
        if not isinstance(arguments, dict):
            return {"status": "blocked", "message": "Blocked: tool arguments must be an object."}

        # Even a hallucinated/unadvertised tool name goes to the gateway. The MCP
        # server rejects it and no upstream session is opened by the gateway.
        result = await self._client.call_tool(name, arguments)
        response_text = "".join(
            content.text for content in result.content if hasattr(content, "text")
        )
        if result.is_error:
            return {"status": "blocked", "message": response_text or "Blocked by AIRLOCK gateway."}
        return {"status": "allowed", "content": response_text}


class MCPGatewayBridge:
    """Discover tools from the AIRLOCK MCP server, not the upstream server."""

    def __init__(self, gateway_client_factory: Any = GatewayMCPClient) -> None:
        self._gateway_client_factory = gateway_client_factory

    async def open(self):
        """Return the downstream MCP context manager for one Gemini request."""
        return self._gateway_client_factory().session()

    @staticmethod
    async def create_session(client: Any) -> GatewayToolSession:
        listed = await client.list_tools()
        tools = [
            GatewayTool(
                name=tool.name,
                description=tool.description or "",
                input_schema=tool.input_schema,
            )
            for tool in listed.tools
        ]
        return GatewayToolSession(client, tools)
