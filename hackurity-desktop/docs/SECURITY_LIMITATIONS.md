# Security protections and limitations

AIRLOCK is a local prototype. This document separates demonstrated controls
from partial work and future work so the security posture is not overstated.

## Implemented protections

| Protection | Current behavior | Evidence |
| --- | --- | --- |
| Deny-by-default authorization | Local policy denies unknown tools, malformed arguments, unlisted actions, and disallowed VM names before forwarding. | `app/policies/json_policy.py`, `tests/test_gateway_integration.py`, `tests/test_reliability.py` |
| No client/LLM authorization claim | Gateway uses a server-side trusted local identity constant rather than request claims. | `app/gateway/gateway_server.py` |
| Tool metadata drift detection | Canonical metadata SHA-256 must match reviewed local approvals; changed definitions are denied until explicit local approval. | `app/gateway/tool_integrity.py`, `app/gateway/tool_approval.py`, `tests/test_tool_integrity.py` |
| Response defense in depth | Bounded scanner can allow, flag, or quarantine selected suspicious instruction patterns. | `app/gateway/response_inspection.py`, `tests/test_response_inspection.py` |
| Auditable enforcement | SQLite records decisions, reasons, execution state, fingerprint/inspection outcome, and sanitized arguments. | `app/audit/sqlite_audit.py`, `tests/test_management_api.py` |
| Local management exposure | Launcher defaults to loopback and API has read-only routes. | `scripts/start_airlock.ps1`, `app/api/management.py` |
| Safe destructive test target | Resource mutations affect only process-local synthetic state. | `mcp_servers/local_server.py`, `tests/test_local_mcp_integration.py` |
| Browser-side text safety | Console inserts API/event values with `textContent`, not `innerHTML`. | `frontend/app.js`, `tests/test_management_api.py` |

## Partially implemented or bounded features

| Area | Actual current boundary |
| --- | --- |
| Identity | One hard-coded, server-side development identity demonstrates non-LLM authorization. There is no user login, token validation, mTLS, or multi-tenant identity mapping. |
| Policy | JSON is deterministic and read-only from the UI. It is not a full policy language, approval workflow with review records, or authenticated administrative API. |
| Tool integrity | Hash covers discovered metadata only: server ID, name, description, and input schema. It does not bind the tool to a signed package, process binary, host, or response data. |
| Response inspection | Rules target known examples and enforce a length limit. Natural language attacks are broader than these patterns, and false positives/negatives are expected. |
| Connection reporting | `/api/connections` reports configured approvals plus observed event history, not live MCP health or active stdio sessions. `active_connections` is intentionally zero. |
| External filesystem connector | The official package was independently launched in a harmless fixture folder, but it is not configured as a gateway upstream and has no AIRLOCK audit/UI integration. |

## Planned improvements, not implemented

- Authenticated and authorized management users, with safe policy editing and
  reviewed change history.
- Authenticated gateway identities and per-identity/per-tool authorization.
- Gateway-only network routing, mutual TLS or transport authentication, and
  process/container isolation of upstream servers.
- Signed/attested upstream packages and server identity verification.
- Stronger schema validation, rate limits, timeouts, resource quotas, and
  cancellation handling.
- More robust semantic response-analysis workflows and human review paths.
- A completed external open-source MCP connector routed through the same
  gateway, fingerprint, policy, audit, and console path.

## Unsupported attack classes

- An upstream server that lies while keeping identical advertised metadata.
- A malicious or compromised local process that edits the policy, approvals,
  SQLite file, or source code.
- Direct network/process access from the client to an upstream server, bypassing
  AIRLOCK.
- Credential theft outside the gateway process, host compromise, or browser
  compromise.
- All prompt injection, indirect prompt injection, covert channels, encoded
  payloads, or data-exfiltration variants.
- Production availability, distributed deployment, high concurrency, disaster
  recovery, or compliance guarantees.

## Operator guidance

Keep the management API on `127.0.0.1`, do not put secrets in policy or tool
arguments, use only the synthetic server for destructive demonstrations, and
review discovered metadata before running the explicit approval command. Treat
this codebase as a transparent local MVP, not a production security boundary.
