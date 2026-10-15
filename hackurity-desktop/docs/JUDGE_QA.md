# Judge Q&A

These answers reflect the code and tests in this repository as of Phase 10.

1. **What problem does AIRLOCK solve?** It makes a server-side security
   decision before an MCP tool request reaches an upstream server. This limits
   an agent's ability to self-authorize a dangerous tool call and produces
   audit evidence for allowed and blocked actions.

2. **Is it a real MCP integration or a REST mock?** It is real local MCP over
   stdio. `LocalMCPClient` and `GatewayMCPClient` use the official Python MCP
   SDK `ClientSession`; tests exercise discovery and calls. The gateway itself
   runs as an MCP server downstream and an MCP client upstream.

3. **Where is the zero-trust decision made?** In `forward()` in
   `app/gateway/gateway_server.py`. It calls local `JsonPolicy.authorize()`
   before opening the upstream execution session. A denied call logs an event
   and returns `ToolError` without being forwarded.

4. **How do you prevent an LLM from claiming administrator privileges?** The
   only identity used by the current policy is the gateway's server-side
   `TRUSTED_IDENTITY` constant. No role, permission, or identity field from a
   downstream tool request is accepted as authorization input. This is a local
   prototype boundary, not full user authentication.

5. **How do you prove a denied call did not execute?** The synthetic upstream
   server exposes execution counters for tests. `test_gateway_integration.py`
   permits one call, then attempts blocked/invalid calls and asserts that their
   counters remain unchanged. It also verifies `upstream_executed=false` in
   audit evidence where applicable.

6. **What is tool poisoning, and how do you address it?** Tool poisoning is
   malicious or misleading tool metadata or output intended to influence an
   agent. AIRLOCK fingerprints reviewed name/description/schema metadata and
   blocks drift; its response scanner separately flags a limited set of
   suspicious instructions in returned text.

7. **What does SHA-256 protect here?** The gateway hashes a stable JSON
   representation of server identity, tool name, description, and input schema.
   It detects a changed reviewed definition. It does not verify the upstream
   executable, its transport identity, or that a tool result is truthful.

8. **Why have both policy checks and fingerprints?** Policy answers “is this
   requested action allowed for these arguments?” Fingerprinting answers “does
   the currently advertised tool definition still match what was reviewed?” A
   match does not grant access; both conditions are required.

9. **How are dangerous tests made safe?** The local server owns only
   in-memory records. `delete_resource` deletes a synthetic record in its own
   process, never a file, cloud resource, or production service. Gateway policy
   does not expose deletion to downstream clients.

10. **What does response inspection do, and what does it not do?** It enforces
    a byte limit and checks a few patterns such as instruction overrides,
    secret-reveal requests, and destructive-tool prompts. Config can allow,
    flag, or quarantine matches. It is a defense-in-depth heuristic, not a
    guarantee against prompt injection or data exfiltration.

11. **How can an operator investigate an event?** Gateway decisions are saved
    in SQLite with timestamp, sanitized arguments, reason, policy/fingerprint/
    inspection states, and whether upstream executed. The read-only FastAPI API
    and browser Activity view retrieve the same data. Sensitive-looking
    argument values are redacted before persistence.

12. **What is innovative, and what remains incomplete?** The prototype shows
    layered MCP-specific controls in a small, inspectable codebase: preflight
    argument policy, metadata drift protection, response inspection, and
    end-to-end audit/UI evidence. It does not authenticate users, enforce
    network-only gateway routing, attest upstream code, or complete the
    official filesystem-server integration through the gateway.
