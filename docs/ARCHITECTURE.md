# AIRLOCK architecture

AIRLOCK is a local security boundary between a downstream MCP client and an
upstream MCP server. Both legs use the official Python MCP SDK over stdio.
The security decision does not depend on the web application.

```text
1. Downstream MCP client
       |
       | stdio: tools/list or tools/call
       v
2. AIRLOCK gateway MCP server
       |-- local JSON policy: authorize trusted identity + arguments
       |-- approved SHA-256 metadata fingerprint check
       |-- SQLite event on every decision
       |
       | (only after allow)
       v
3. Upstream synthetic MCP server
       |
       | tool result
       v
4. Gateway response inspector
       |-- allow / flag / quarantine
       v
5. MCP client receives result or MCP ToolError

SQLite audit database <- FastAPI read endpoints <- browser console
```

## Components and trust boundaries

| Component | Actual code | Trust role |
| --- | --- | --- |
| Downstream test client | `app/gateway/gateway_client.py` | Sends MCP requests; it is not trusted to declare permissions. |
| Gateway server | `app/gateway/gateway_server.py` | Security enforcement point. It is both an MCP server and an MCP client. |
| Policy engine | `app/policies/json_policy.py`, `config/policy.json` | Makes deterministic server-side allow/deny decisions. |
| Approval registry | `app/gateway/tool_integrity.py`, `config/tool_approvals.json` | Stores reviewed metadata fingerprints. |
| Upstream server | `mcp_servers/local_server.py` | Safe, process-local test target; its definitions and responses remain untrusted. |
| Response inspector | `app/gateway/response_inspection.py` | Finds a limited set of suspicious instructions in returned text. |
| Audit database | `app/audit/sqlite_audit.py` | Stores security evidence in SQLite. |
| Management API/UI | `app/api/management.py`, `frontend/` | Read-only visibility layer; it cannot authorize a call. |

## Complete call flow

1. `GatewayMCPClient.session()` starts `python -m app.gateway.gateway_server`
   and initializes a real MCP stdio `ClientSession`.
2. At startup, `create_gateway_server()` starts a temporary upstream
   `LocalMCPClient` session and discovers tool metadata.
3. The gateway exposes only tool names that are both allowed by the local
   policy and present in the approval registry with the expected fingerprint.
   In the supplied configuration these are `list_resources` and `restart_vm`.
   `delete_resource` is deliberately absent from the downstream tool list.
4. A downstream `tools/call` reaches the nested `forward()` function in
   `gateway_server.py`.
5. Before opening an upstream execution session, `JsonPolicy.authorize()`
   evaluates the trusted constant `local-development-agent`, tool name, and
   arguments. Unknown tools, malformed arguments, other VM names, and
   `delete_resource` are denied. The client never supplies the identity used
   for this decision.
6. On denial, the gateway writes a SQLite event with `upstream_executed=false`
   and returns an MCP `ToolError`. It does not open a forwarding session.
7. On allow, the gateway rediscovers definitions in the execution session and
   uses `ApprovalRegistry.is_approved()` to recompute the canonical SHA-256
   fingerprint. A missing or changed definition becomes an integrity denial;
   no tool call is forwarded.
8. Only after both checks does the gateway call
   `upstream_session.call_tool(tool_name, arguments)` using MCP.
9. The result text goes to `ResponseInspector.inspect()`. The gateway records
   the inspection outcome. Clean responses pass; suspicious responses follow
   the configured `allow`, `flag`, or `quarantine` action.
10. FastAPI reads the same SQLite data through `SQLiteAuditLog`; the browser
    fetches those read-only endpoints and renders the fields as text.

## Policy currently enforced

`config/policy.json` contains a default-deny policy for the sole local trusted
identity. It permits no-argument `list_resources` and permits `restart_vm`
only when `resource_name` is `dev-vm-01`. It does not allow `delete_resource`.
Policy evaluation fails closed when the expected structure or arguments cannot
be validated.

## Tool integrity

The canonical value is a stable JSON object containing server identity, tool
name, description, and input schema. `json.dumps(..., sort_keys=True,
separators=(",", ":"))` produces a predictable byte sequence; SHA-256 hashes
that sequence. This detects metadata drift, such as a tool description changed
to include malicious instructions. It does not attest to what the tool process
actually does or whether a result is true.

## Audit and dashboard flow

`SQLiteAuditLog.record_event()` stores UTC timestamp, upstream server/tool,
sanitized arguments, allow/deny decision, policy/reason, fingerprint result,
response-inspection result, and whether upstream execution occurred. Argument
keys containing terms such as `secret`, `password`, `token`, `api_key`, or
`credential` are replaced with `[REDACTED]` before persistence.

`create_management_app()` mounts the browser frontend after registering `/api`
routes. `/api/summary`, `/api/events`, and `/api/connections` derive their
answers from SQLite/configuration. The application intentionally reports no
live active sessions because stdio requests are short-lived.

## Deployment boundary

The bundled PowerShell launcher binds the API to `127.0.0.1`, but this is not a
production authentication solution. A client capable of contacting the
upstream server directly can bypass the gateway. A real deployment needs
gateway-only network paths, authenticated identities, upstream provenance or
attestation, and hardened process isolation.
