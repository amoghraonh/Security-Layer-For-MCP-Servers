# Code walkthrough

This walkthrough describes code currently in the repository. Paths below are
also the quickest trace from a claim to its implementation or test.

## MCP and gateway

| File / important item | What it does and why | Callers, data, and security role |
| --- | --- | --- |
| `mcp_servers/local_server.py` / `SyntheticResourceStore` | Holds three harmless resource records in memory. `reset()` restores the initial set, so tests are repeatable. | The three MCP tools call it with resource names and return JSON/text. It never contacts real infrastructure. |
| `mcp_servers/local_server.py` / `list_resources`, `restart_vm`, `delete_resource` | Registers the upstream tools using the MCP SDK. | An MCP client discovers them using `tools/list` and invokes them with `tools/call`. `restart_vm` and `delete_resource` mutate only the process-local store. |
| `app/gateway/mcp_client.py` / `LocalMCPClient` | Starts the synthetic server as `python -m mcp_servers.local_server` over stdio. | `discover_tool_definitions()` initializes an MCP session and returns `DiscoveredTool` values. `session()` yields a real SDK `ClientSession` for calls. |
| `app/gateway/gateway_client.py` / `GatewayMCPClient` | Test/demo downstream client for the gateway process. | Tests call `session()`; it starts `python -m app.gateway.gateway_server`, initializes MCP, then yields a client session. |
| `app/gateway/gateway_server.py` / `create_gateway_server()` | Builds AIRLOCK's downstream MCP server after discovering and filtering upstream tools. | `run_gateway()` calls it. The startup filter requires both a local policy allowance and a known metadata fingerprint, which keeps `delete_resource` out of the exposed list. |
| `gateway_server.py` / `forward()` | The central security boundary. | Tool wrappers pass a tool name and argument dictionary. It authorizes first, audits denials, rechecks the upstream definition, then calls upstream only if all checks pass. Its order is why denied calls do not reach upstream. |
| `gateway_server.py` / `TRUSTED_IDENTITY` | A server-side identity constant for this local prototype. | Policy receives this constant rather than an LLM/client-provided claim. It demonstrates the boundary but is not a multi-user authentication system. |

## Authorization and integrity

| File / important item | What it does and why | Callers, data, and security role |
| --- | --- | --- |
| `app/policies/json_policy.py` / `JsonPolicy.from_file()` | Loads local JSON policy into a small evaluator. | Gateway startup calls it with `config/policy.json`. Keeping the policy local avoids granting authority to prompt text or the UI. |
| `json_policy.py` / `authorize()` | Returns a decision object for identity, tool name, and arguments. | `forward()` calls it before an upstream session. It validates no-argument list requests and restricts VM restart to `dev-vm-01`; invalid data is denied. |
| `app/gateway/tool_integrity.py` / `DiscoveredTool` | Represents discovered server identity, name, description, and input schema. | `LocalMCPClient` creates these from `tools/list`; approval code hashes them. |
| `tool_integrity.py` / canonicalization and `fingerprint()` | Serializes the four approved metadata fields in sorted compact JSON, then computes SHA-256. | `ApprovalRegistry.is_approved()` compares the current hash with local reviewed data. Stable serialization means equivalent field order produces the same fingerprint. |
| `tool_integrity.py` / `ApprovalRegistry` | Reads approval records and only recognizes exact matches. | Gateway uses it once to decide what to expose and again immediately before forwarding. Unknown or changed metadata is denied. |
| `app/gateway/tool_approval.py` | Deliberate administrator CLI for writing fresh approvals. | The operator runs `python -m app.gateway.tool_approval approve --all-discovered` after review. The gateway never auto-approves a discovery. |
| `config/policy.json`, `config/tool_approvals.json` | The supplied policy and reviewed hashes. | They are operational configuration, not generated dashboard data. Changes should be reviewed because they change security behavior. |

## Responses and evidence

| File / important item | What it does and why | Callers, data, and security role |
| --- | --- | --- |
| `app/gateway/response_inspection.py` / `ResponseInspector` | Loads scanner action and byte limit, then evaluates returned text against a small rule set. | `forward()` gives it assembled upstream text after execution. It is defense in depth, not a pre-execution authorization mechanism. |
| `response_inspection.py` / `inspect()` | Returns whether text is suspicious and which patterns matched. | Oversize text and phrases such as instruction override or secret-exfiltration requests can trigger. `allow` retains text, `flag` returns a documented JSON envelope, and `quarantine` returns a ToolError. |
| `app/audit/sqlite_audit.py` / `sanitize_arguments()` | Recursively removes values for sensitive-looking key names. | `record_event()` calls it before storing a JSON string, reducing accidental credential persistence. |
| `sqlite_audit.py` / `SQLiteAuditLog` | Creates/queries the SQLite table and calculates summaries. | Gateway writes events; FastAPI calls `summary()`, `events()`, `event()`, and `connections()`. Each operation uses a short SQLite connection. |
| `config/response_inspection.json` | Current scanner configuration. | The gateway reads it at startup. The shipped action is `flag`, so detected output is preserved inside a visible envelope rather than silently changed. |

## API and browser console

| File / important item | What it does and why | Callers, data, and security role |
| --- | --- | --- |
| `app/api/management.py` / `create_management_app()` | Creates FastAPI routes and mounts the static frontend. | `run_management.py` starts it. All management endpoints are GET-only; policy edits remain local files because no authenticated write path exists. |
| `management.py` / `/api/health`, `/api/summary`, `/api/events`, `/api/events/{id}` | Returns liveness and actual stored audit data. | Browser JavaScript fetches the collection endpoints. Query validation restricts event limits; unknown event IDs return 404. |
| `management.py` / `/api/connections`, `/api/policies` | Returns observed audit server aggregation plus approval/policy configuration. | The connection list is not a live session monitor; it combines config and prior audit records. |
| `app/api/run_management.py` | Reads host/port environment settings and runs Uvicorn. | `scripts/start_airlock.ps1` launches it with loopback defaults. |
| `frontend/index.html` | Semantic layout for Overview, Activity, Policies, Connections, and event detail UI. | The browser loads it through FastAPI static files. It contains no hard-coded security events. |
| `frontend/styles.css` | Light, responsive visual treatment for desktop/mobile states. | The HTML imports it. Colors distinguish allowed and blocked actions without visual effects that hide data. |
| `frontend/app.js` | Fetches API data, handles loading/error/empty/search states, and fills the DOM. | It renders untrusted values with `textContent`, avoiding HTML insertion/XSS from audit data. |
| `scripts/start_airlock.ps1` | Windows-oriented launcher that starts the management service and waits for its health endpoint. | A developer runs it from PowerShell. It does not start a publicly exposed service. |

## Tests as executable documentation

| Test | Working behavior proved |
| --- | --- |
| `tests/test_project_foundation.py` | Package imports and baseline policy behavior. |
| `tests/test_local_mcp_integration.py` | Real synthetic stdio `tools/list`, successful calls, unknown-resource errors, and unknown-tool errors. |
| `tests/test_gateway_integration.py` | Gateway exposes approved tools; allowed calls increment upstream evidence; denied/invalid/unknown calls do not execute upstream. |
| `tests/test_tool_integrity.py` | A changed description is rejected until deliberate reapproval. |
| `tests/test_response_inspection.py` | Benign phrasing, suspicious patterns/limits, and allow/flag/quarantine actions. |
| `tests/test_management_api.py` | Sanitization, an actual MCP-generated audit event, API retrieval, and static console serving. |
| `tests/test_reliability.py` | API 404/validation errors, fail-closed policy behavior, and empty database/no fake activity. |

The official Node filesystem connector experiment is in
`external_filesystem_connector/`. `discover.py` independently uses MCP but is
not called by the gateway, so it is intentionally not listed as an integrated
component.
