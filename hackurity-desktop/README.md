# AIRLOCK

AIRLOCK is a local, zero-trust security gateway for Model Context Protocol
(MCP) tool calls. It sits between an MCP client and an upstream MCP server,
allows only explicitly approved operations, records the decision in SQLite,
and inspects returned text for a small set of prompt-injection indicators.

It is a working hackathon prototype built with Python, the official Python MCP
SDK, FastAPI, SQLite, pytest, and a vanilla HTML/CSS/JavaScript console. The
`hackurity-desktop` console includes a real login gate, role-aware management
actions, three-lane access control, policy dry-runs, an isolated attack lab,
bounded file scanning, authentication events, and JSON evidence export.

## The problem

An AI agent can ask an MCP server to perform real-world actions. A tool name,
an LLM-generated role claim, or a friendly-looking tool description must not be
treated as authorization. AIRLOCK makes a server-side policy decision before
an upstream tool call is made, then retains evidence of that decision.

The included upstream server is deliberately synthetic: it keeps three
resources in process memory and never calls a cloud provider, shell, or real
infrastructure.

## Working architecture

```text
MCP client --stdio--> AIRLOCK gateway --stdio--> synthetic upstream MCP server
                         |      |                         |
                    JSON policy  SHA-256 approvals     synthetic resources
                         |
                    SQLite audit log <-- FastAPI <-- security console
```

The gateway is operational without the dashboard. The dashboard is a
read-only localhost view of the audit database. See
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full request path.

## Implemented features

- Real MCP stdio discovery and invocation of `list_resources`, `restart_vm`,
  and `delete_resource` on the synthetic upstream server.
- An MCP intermediary that exposes only policy-approved, fingerprint-approved
  upstream tools to downstream clients.
- Deny-by-default authorization. `list_resources` is allowed; `restart_vm` is
  allowed only for `dev-vm-01`; `delete_resource` is not exposed.
- Canonical metadata fingerprints using stable JSON and SHA-256, with an
  explicit local administrator approval command.
- Configurable bounded response inspection (`allow`, `flag`, or `quarantine`)
  for a small set of suspicious instruction patterns.
- SQLite audit events with sanitized sensitive argument names.
- FastAPI management APIs with Argon2id-backed local accounts, opaque
  HTTP-only sessions, role checks, deterministic policy simulation, and a
  responsive dark security console using real API data.
- A non-executing file scanner endpoint for bounded text/source inspection,
  synthetic attack scenarios, authentication-event visibility, and verified
  audit JSON export.
- Automated tests for MCP communication, authorization, integrity, inspection,
  audit/API behavior, and fail-closed cases.
- Optional Gemini Agent Playground integration using the official
  `google-genai` SDK. Gemini sees only tools discovered from the AIRLOCK
  gateway; every requested call returns through that gateway.

## Repository map

- `app/gateway/` — the downstream MCP server, upstream MCP client, integrity
  approval logic, and response inspection.
- `app/policies/` — deterministic local JSON authorization evaluation.
- `app/audit/` — SQLite event storage and argument sanitization.
- `app/api/` — read-only FastAPI management API and Uvicorn launcher.
- `mcp_servers/` — the safe in-memory upstream MCP server.
- `frontend/` — static console (`index.html`, `styles.css`, `app.js`).
- `config/` — policy, approval registry, and inspection configuration.
- `tests/` — pytest coverage of real local MCP flows and management APIs.
- `scripts/start_airlock.ps1` — Windows-friendly console/API launcher.
- `external_filesystem_connector/` — an independently verified official
  filesystem-server experiment; it is not yet connected through the gateway.

## Requirements

- Python 3.11+ (the current environment was tested with Python 3.12).
- Windows PowerShell for the commands below.
- Node.js is optional. It is only needed for the separate filesystem connector
  experiment described in `external_filesystem_connector/`.

## Install and verify (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -c "from importlib.metadata import version; print(version('mcp'))"
python -m pytest -q
```

If PowerShell blocks activation, allow it for the current shell only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Run the console

```powershell
.\scripts\start_airlock.ps1
```

The script starts FastAPI on `127.0.0.1:8000`, waits for `/api/health`, and
prints the URL. Open `http://127.0.0.1:8000/`. The console shows an empty state
until the gateway processes a call; it never invents activity data.

To create real local gateway events, run:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_gateway_integration.py -v
```

Refresh the console and inspect **Activity**. This test makes actual MCP stdio
calls against the synthetic upstream server and writes gateway audit events to
the default local SQLite database.

## Gemini Agent Playground

Install the new dependencies, then put `GEMINI_API_KEY` and optionally
`GEMINI_MODEL` in a local `.env` file. `.env` is ignored by Git and is never
served to the browser. Start the console and open **Agent Playground**. Its
browser code posts a message to `POST /api/chat`; the server creates the Gemini
request and manually executes any requested function through the AIRLOCK MCP
gateway.

```powershell
python -m pip install -r requirements.txt
Copy-Item .env.example .env
# Edit .env locally; do not commit it.
.\scripts\start_airlock.ps1
```

The server applies a Mission Lock system instruction and exposes only the
gateway's currently discovered tools. Gemini tool calls are not executed by the
SDK automatically. See [docs/GEMINI_INTEGRATION.md](docs/GEMINI_INTEGRATION.md)
for the flow and live-verification steps.

## Reproduce the core behavior

```powershell
# Real upstream MCP discovery/calls
.\.venv\Scripts\python.exe -m pytest tests\test_local_mcp_integration.py -v

# Gateway: allowed call reaches upstream; denied calls do not
.\.venv\Scripts\python.exe -m pytest tests\test_gateway_integration.py -v

# Changed tool definition is blocked until explicit reapproval
.\.venv\Scripts\python.exe -m pytest tests\test_tool_integrity.py -v

# Response scanner behaviors
.\.venv\Scripts\python.exe -m pytest tests\test_response_inspection.py -v
```

After a deliberate review of discovered metadata, regenerate the local approval
registry with:

```powershell
.\.venv\Scripts\python.exe -m app.gateway.tool_approval approve --all-discovered
```

This command trusts the currently discovered metadata; it must be a conscious
administrator action, not an automatic gateway behavior.

## Management API

All endpoints are read-only and are intended for loopback use:

- `GET /api/health`
- `GET /api/summary`
- `GET /api/events?limit=100`
- `GET /api/events/{id}`
- `GET /api/connections`
- `GET /api/policies`

## Screenshots

No durable screenshot artifact is committed to this repository. Run the
localhost console with the command above to view actual event data rather than
static or fake screenshots.

## Test evidence

The most recent documented full suite result from Phase 9 was **17 passed**:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Run the command locally to reproduce it in your environment. The individual
tests are mapped to features in [docs/CODE_WALKTHROUGH.md](docs/CODE_WALKTHROUGH.md).

## Known limitations

- The gateway has one trusted, server-configured local identity; it does not
  authenticate human users or verify LLM role claims.
- Tool fingerprints cover advertised metadata, not the upstream server binary,
  behavior, transport identity, or response truthfulness.
- The rule-based scanner is defense in depth, not complete prompt-injection
  detection; it can miss attacks and flag benign text.
- MCP stdio sessions are short-lived, so `active_connections` is reported as
  zero rather than as a live connection monitor.
- Health and compatibility telemetry endpoints remain intentionally local;
  protected policy, scanner, approval, and authentication-event operations
  require an HTTP-only session and an allowed role.
- Direct client-to-upstream configuration bypasses AIRLOCK entirely.
- The official filesystem MCP package was independently exercised in a
  restricted fixture folder, but is **not integrated** into the gateway,
  approval registry, audit trail, or console. Therefore Phase 8's end-to-end
  external connector acceptance is incomplete.

Read [docs/SECURITY_LIMITATIONS.md](docs/SECURITY_LIMITATIONS.md) before using
this prototype outside the safe local demonstration.

## Phase 10 documentation checklist

- [x] Product overview, install/run commands, architecture, and limitations.
- [x] Full request-path architecture explanation.
- [x] Plain-English implementation and test walkthrough.
- [x] Reproducible 3–5 minute safe demo guide.
- [x] Twelve judge questions with code-backed answers.
- [x] Team speaking scripts mapped to working code.
- [x] Clear implemented/partial/planned/unsupported security boundaries.
- [ ] End-to-end external filesystem connector inside the AIRLOCK gateway.
