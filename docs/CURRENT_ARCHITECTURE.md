# Current architecture assessment

This document records the repository state after Phase 1 local-data gateway
integration. It distinguishes working behavior from planned enterprise work.

## Components present today

```text
Browser security console / Agent Playground
  └─ FastAPI management application (`app/api/management.py`)
       ├─ GET audit, policy, connection, and health APIs
       └─ POST /api/chat
            └─ GeminiMcpController (`app/agent/controller.py`)
                 ├─ GeminiProvider (official `google-genai` SDK)
                 └─ GatewayMCPClient (MCP stdio)
                      └─ AIRLOCK gateway (`app/gateway/gateway_server.py`)
                           ├─ deterministic JSON policy
                           ├─ approved SHA-256 tool metadata registry
                           ├─ response-instruction scanner
                           ├─ SQLite audit log
                           └─ LocalMCPClient (MCP stdio)
                                └─ local synthetic MCP server
                                     ├─ in-memory synthetic resources
                                     ├─ public local Git fixture (read-only)
                                     └─ fictional Azure-style JSON inventory (read-only)
```

## Backend and protocol facts

- The backend is FastAPI. `create_management_app()` mounts the static vanilla
  frontend and provides read-only management endpoints plus `POST /api/chat`.
- The installed MCP SDK is used for real stdio initialization, `tools/list`,
  and `tools/call`; it is not replaced with a REST mock.
- `GatewayMCPClient` starts AIRLOCK as a downstream MCP server. The gateway
  starts `LocalMCPClient` only after its own policy and integrity checks pass.
- The gateway uses a trusted server-side local identity, not an LLM role claim.
- `GeminiMcpController` turns only gateway-discovered tools into Gemini
  declarations and disables SDK automatic function execution. It manually feeds
  every model-requested call into the gateway.

## Current local server tools

| Tool | Data/action | Gateway status |
| --- | --- | --- |
| `list_resources` | List three synthetic in-memory resources | Allowed |
| `restart_vm` | Restart only `dev-vm-01` in memory | Allowed for that VM |
| `delete_resource` | Delete only a synthetic in-memory resource | Not exposed/denied |
| `list_local_repository_files` | List a bounded public local Git fixture | Allowed |
| `read_local_repository_file` | Read bounded UTF-8 text below approved prefixes | Allowed by path scope |
| `list_synthetic_azure_resources` | List fictional local JSON metadata | Allowed |
| `get_synthetic_azure_resource` | Read an explicitly allowlisted fictional resource | Allowed by name scope |

## Deterministic security controls working now

1. `JsonPolicy.authorize()` defaults to deny and validates tool-specific
   arguments before the gateway opens an upstream execution session.
2. `ApprovalRegistry.is_approved()` verifies the server identity, tool name,
   description, and input schema fingerprint. New data tools were approved
   through `app.gateway.tool_approval`, not automatically trusted.
3. `ResponseInspector` scans bounded upstream response text and follows its
   configured allow/flag/quarantine action.
4. `SQLiteAuditLog` stores the decision, sanitized arguments, reason,
   fingerprint state, response-inspection outcome, and upstream-executed flag.
   It also stores a deterministic risk score/category/factors for operators;
   this score never changes an authorization decision.
5. The repository fixture implementation rejects path escapes, binary text, and
   files over 64 KiB. The Azure fixture is a committed local JSON document, not
   a live Azure request.

## Critical weaknesses and limits

- Application authentication, user sessions, roles, mission TTL, approval
  workflow, DLP scanning, tamper-evident audit records, and risk scoring are
  not implemented yet.
- The single `TRUSTED_IDENTITY` demonstrates server-side authorization but is
  not user authentication.
- Gemini live requests require a valid server-side `GEMINI_API_KEY`; this
  workspace currently cannot claim a live successful request without it.
- The Mission Lock is a Gemini system instruction, not an independent mission
  authorization model. Gateway policy remains the effective enforcement layer.
- A client configured to contact an upstream MCP server directly can bypass the
  gateway; this local prototype has no network-level enforcement.
- No official GitHub or Azure MCP server is connected yet. The Git and Azure
  data in the local server is safe local fixture data only.

## Planned improvements

The next phases should add official external connector discovery behind the
same gateway, then independently enforced identity/mission/approval controls,
risk and DLP signals, tamper-evident audit data, and a UI that surfaces only
real backend events. Each addition requires new tests and explicit limitations.
