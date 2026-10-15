# Team explanation and speaking scripts

The roles below map to the working repository. They do not claim features that
are only planned or experimentally verified outside the gateway.

## Medha — problem and user interface

**Role:** Explain the user problem and show the management console.

**Script (about 45 seconds):** “AI agents can use MCP tools to take actions,
but a natural-language instruction or an agent-generated role should never be
permission by itself. AIRLOCK adds a gate before the upstream tool call. The
browser console is a read-only view of the security evidence, built in plain
HTML, CSS, and JavaScript. Overview shows real totals from SQLite; Activity
shows actual decisions and details; Policies explains the locally configured
rules; and Connections shows approved fingerprint status. It handles empty,
loading, and error states, and renders event text safely with `textContent`.”

**Evidence:** `frontend/index.html`, `frontend/app.js`, `frontend/styles.css`,
`app/api/management.py`, `tests/test_management_api.py`.

## Juhitha — attack scenarios and response inspection

**Role:** Explain the attack model after a tool has returned content.

**Script (about 45 seconds):** “An upstream tool response is data, not trusted
instructions. A poisoned response might say to ignore previous instructions,
reveal a token, override the system message, or invoke an unrelated destructive
tool. Our rule-based response inspector checks a bounded amount of returned
text for those examples. The local configuration chooses whether to allow it,
return a visible flag envelope that preserves the original, or quarantine it.
This is not perfect prompt-injection detection; it is an additional layer after
authorization, and every outcome is audited.”

**Evidence:** `app/gateway/response_inspection.py`,
`config/response_inspection.json`, `tests/test_response_inspection.py`.

## Amogh — gateway architecture and security enforcement

**Role:** Explain the MCP flow and pre-execution controls.

**Script (about 60 seconds):** “AIRLOCK is an MCP server toward the agent and
an MCP client toward the upstream tool server, using stdio on both sides. It
discovers the upstream definitions and exposes only tools that have both a
reviewed fingerprint and a policy allowance. For each call, `forward()` runs
the local JSON policy before opening an upstream execution session. The trusted
identity is server-configured; an LLM cannot pass a role claim to authorize
itself. A permitted restart is restricted to `dev-vm-01`; deletion is not
exposed. Before forwarding, the gateway checks the tool metadata fingerprint
again. Tests use upstream counters to prove blocked calls never ran.”

**Evidence:** `app/gateway/gateway_server.py`,
`app/policies/json_policy.py`, `app/gateway/tool_integrity.py`,
`tests/test_gateway_integration.py`, `tests/test_tool_integrity.py`.

## Pavan — backend, tests, and local deployment

**Role:** Explain persistence, testing, and how to run the prototype.

**Script (about 45 seconds):** “The gateway writes SQLite audit events with
sanitized arguments, the decision reason, fingerprint and scanner status, and
whether the upstream server executed. FastAPI exposes read-only localhost APIs,
and the PowerShell launcher starts it and checks health. The pytest suite uses
real synthetic MCP processes to cover discovery, allow/deny behavior, invalid
arguments, fingerprint changes, suspicious responses, audit/API correctness,
and fail-closed behavior. We deliberately keep destructive scenarios synthetic
and in memory.”

**Evidence:** `app/audit/sqlite_audit.py`, `app/api/management.py`,
`scripts/start_airlock.ps1`, `tests/`.

## Handoff line

“For a live proof, we run the gateway integration test, then refresh the local
console to see the resulting audit events. The demo guide gives the exact
commands and the honest limitations.”
