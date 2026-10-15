# Gemini integration

## What is implemented

`app/agent/gemini_provider.py` uses the official `google-genai` Python SDK.
It reads `GEMINI_API_KEY` and `GEMINI_MODEL` only in the server process after
loading a local `.env` file. The browser never receives either value. Missing
keys return a clear `503` from `POST /api/chat`; provider rate-limit, timeout,
and unavailable-model errors are returned as safe `502` messages.

`GeminiMcpController` does not give Gemini direct upstream access. For each
browser message it:

1. Starts a downstream `GatewayMCPClient` session to AIRLOCK.
2. Calls `tools/list` on the **gateway**, not the synthetic upstream server.
3. Converts only those returned tool definitions into Gemini function
   declarations.
4. Sends the user message and Mission Lock instruction to Gemini with automatic
   function calling disabled.
5. For every function request, calls the gateway through MCP stdio.
6. Feeds the gateway's allowed result or blocked error text back to Gemini as a
   function response, then returns Gemini's next text reply.

The existing gateway still performs its policy authorization, fingerprint
verification, upstream call, response inspection, and SQLite audit work. The
Gemini adapter does not implement an alternate path around those controls.

## Files

- `app/agent/gemini_provider.py` — SDK configuration, provider error handling,
  Mission Lock, and conversion between Gemini function calls/responses.
- `app/agent/mcp_gateway_bridge.py` — MCP tool discovery and call adapter that
  targets `GatewayMCPClient` only.
- `app/agent/controller.py` — bounded manual tool loop; `MAX_TOOL_ROUNDS` is 4.
- `app/api/management.py` — `POST /api/chat` with bounded message validation.
- `frontend/index.html`, `frontend/app.js`, `frontend/styles.css` — Agent
  Playground UI. It uses `textContent` for returned content.
- `tests/test_gemini_mcp_integration.py` — real AIRLOCK MCP gateway with a
  deterministic provider substitute; no external model request is faked.

## Local setup

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set these local-only values in `.env`:

```text
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-2.5-flash
```

Do not commit `.env`, expose it through FastAPI, or paste the key into browser
JavaScript. `.gitignore` excludes it.

## Live verification

With a valid local key and an available configured model:

1. Start the server: `./scripts/start_airlock.ps1`.
2. In Agent Playground, submit `Hello AIRLOCK`. Gemini should return text and
   no tool result.
3. Submit `List my cloud resources`. Gemini may select `list_resources`; when
   it does, Activity records an allowed, upstream-executed audit event.
4. Submit `Delete the production database`. `delete_resource` is absent from
   the gateway-discovered tools. If the model nevertheless requests that name,
   the controller submits it to AIRLOCK, which rejects it as an unknown
   downstream tool before upstream execution. The model receives a blocked
   message.

Tool selection is model behavior, so a natural-language request cannot prove a
tool invocation by itself. Inspect returned `tool_results` and the real audit
activity rather than claiming a call occurred from the text reply alone.

## Current verification status

The SDK import and API types were verified with installed `google-genai`
version 1.75.0. `tests/test_gemini_mcp_integration.py` passed using a
deterministic provider that requests an allowed tool and then a deletion tool:
the MCP gateway and its upstream counter are real in both cases.

A live `generate_content` call cannot be verified in this workspace until a
local `.env` or process environment actually supplies `GEMINI_API_KEY`. The
adapter therefore must not be described as a verified live Gemini-to-MCP
integration yet.
