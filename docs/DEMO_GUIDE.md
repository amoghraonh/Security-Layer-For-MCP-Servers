# 3–5 minute live demo guide

This demonstration uses only the repository's safe synthetic upstream server.
It creates actual MCP traffic, audit records, and console data.

## Before the demo

Open PowerShell in the repository and install dependencies as described in the
README. Then start the management service:

```powershell
.\scripts\start_airlock.ps1
```

Open `http://127.0.0.1:8000/`. The Overview may show zero events initially;
that is the correct empty state, not a failed dashboard.

## Suggested script

### 0:00–0:40 — state the security boundary

Say: “AIRLOCK sits between an AI agent and an MCP tool server. The agent is
not trusted to grant itself permissions. The gateway evaluates trusted local
policy before it opens an upstream execution session.”

In the browser, show **Policies**. Point out that the policy permits
`list_resources`, permits `restart_vm` only for `dev-vm-01`, and does not
permit deletion.

### 0:40–1:20 — show real tool discovery

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_local_mcp_integration.py -v
```

Say: “This test starts the local server over stdio and uses the MCP client SDK
to send `tools/list` and `tools/call`. The server only owns in-memory synthetic
resources, so there is no cloud account or real VM involved.”

The visible test names cover discovery, successful calls, unknown resources,
and error handling.

### 1:20–2:30 — prove one allowed call and one blocked call

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_gateway_integration.py -v
```

Say: “This is real MCP on both sides of the gateway. The allowed
`restart_vm(dev-vm-01)` reaches the upstream server. The test sets an execution
counter on that safe server. It also attempts a blocked VM restart and an
unapproved tool, then proves their counters did not change. That is evidence
that AIRLOCK did not forward denied requests.”

If asked where enforcement occurs, open `app/gateway/gateway_server.py` and
point to `forward()`: `policy.authorize()` occurs before
`upstream_client.session()`.

### 2:30–3:20 — show audit evidence in the console

Return to the browser and refresh. Open **Activity**, search for
`restart_vm`, and click an event.

Say: “These records came from the gateway's SQLite audit log. An allowed event
has `upstream_executed=true`; a policy denial has
`upstream_executed=false`. The UI fetches this data from FastAPI; it does not
contain a hard-coded incident list.”

Show **Overview** for real totals, then **Connections** to show approved
fingerprint status and whether each configured tool is exposed by policy.

### 3:20–4:10 — show metadata and response defenses

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_tool_integrity.py tests\test_response_inspection.py -v
```

Say: “A tool's reviewed metadata—server identity, name, description, and input
schema—is canonicalized and SHA-256 hashed. A changed malicious description is
blocked until an administrator intentionally approves it. Returned tool text is
also treated as untrusted: the scanner can allow, visibly flag, or quarantine
a limited list of suspicious instruction patterns.”

### 4:10–4:40 — close with honest limits

Say: “This is a zero-trust gateway prototype, not a complete sandbox. Hashing
does not prove the server implementation or result truthfulness, the scanner
is not perfect prompt-injection detection, the API is localhost-only because
it has no authentication, and direct access to an upstream server bypasses the
gateway.”

## Recovery notes

- If the console is blank after the gateway test, refresh the page. The test
  writes the default `data/sentry_x_audit.db`, and the API reads it on request.
- If the port is in use, choose a different one:

```powershell
.\scripts\start_airlock.ps1 -Port 8011
```

- Do not demo `delete_resource` as a permitted gateway action. Its absence from
  the downstream tool list is the intentional result.
