"""Agent controller that sequences Gemini function calls through AIRLOCK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from google.genai import types

from app.agent.gemini_provider import GeminiProvider, GeminiServiceError
from app.agent.mcp_gateway_bridge import MCPGatewayBridge


MAX_TOOL_ROUNDS = 4


@dataclass(frozen=True)
class ChatResult:
    """Safe response returned by the HTTP chat endpoint."""

    answer: str
    tool_results: list[dict[str, Any]]


class GeminiMcpController:
    """Keep Gemini reasoning separate from all privileged MCP execution."""

    def __init__(self, provider: GeminiProvider | None = None, bridge: MCPGatewayBridge | None = None) -> None:
        self._provider = provider or GeminiProvider()
        self._bridge = bridge or MCPGatewayBridge()

    async def handle_message(self, message: str) -> ChatResult:
        """Discover gateway tools, run Gemini, and feed gateway results back to Gemini."""
        cleaned_message = message.strip()
        if not cleaned_message:
            raise ValueError("Message must not be empty")

        context_manager = await self._bridge.open()
        async with context_manager as client:
            gateway = await self._bridge.create_session(client)
            tools = gateway.gemini_tools()
            conversation: list[Any] = [types.Content(role="user", parts=[types.Part.from_text(text=cleaned_message)])]
            tool_results: list[dict[str, Any]] = []

            for _ in range(MAX_TOOL_ROUNDS + 1):
                reply = await self._provider.generate(conversation, tools)
                if not reply.function_calls:
                    return ChatResult(answer=reply.text or "Gemini returned no text.", tool_results=tool_results)

                if len(tool_results) >= MAX_TOOL_ROUNDS:
                    return ChatResult(
                        answer="Tool request limit reached; no further tools were executed.",
                        tool_results=tool_results,
                    )

                results_for_model: list[tuple[str, dict[str, Any]]] = []
                for call in reply.function_calls:
                    result = await gateway.call(call.name, call.arguments)
                    result_record = {"tool": call.name, **result}
                    tool_results.append(result_record)
                    results_for_model.append((call.name, result))

                if reply.raw_content is not None:
                    conversation.append(reply.raw_content)
                conversation.append(self._provider.tool_response_content(results_for_model))

        raise GeminiServiceError("Gemini continued requesting tools beyond the configured safety limit")
