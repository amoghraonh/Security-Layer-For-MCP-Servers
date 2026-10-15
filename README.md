# 🛡️ AIRLOCK — Zero-Trust AI Agent Security Gateway

**AI Moves. AIRLOCK Decides.**

AIRLOCK is a cybersecurity project for controlling what AI agents can do with external tools. It combines a Gemini-powered AI assistant with the architecture of an independent security gateway for **Model Context Protocol (MCP)** connections such as GitHub, Azure, and a local attack-testing server.

An AI agent can propose actions; **AIRLOCK is designed to decide whether a protected tool action is allowed, requires human review, or must be denied before execution.**

> **Project-status note:** This README is based on the AIRLOCK prototype and project design shared so far, not a verified checkout of the latest source code. The Python/Gemini assistant has been demonstrated previously. Gateway enforcement, GitHub/Azure integrations, sandbox, caching, admin functions, and frontend capabilities must each be checked in the actual repository before being marked as working. Sections marked **if implemented** are usage guides for those modules, not claims of completion.

## Contents

1. [What problem does AIRLOCK solve?](#what-problem-does-airlock-solve)
2. [Features and development status](#features-and-development-status)
3. [How AIRLOCK works](#how-airlock-works)
4. [Requirements](#requirements)
5. [Quick start — Windows PowerShell](#quick-start--windows-powershell)
6. [How to use AIRLOCK](#how-to-use-airlock)
7. [GitHub MCP setup](#github-mcp-setup)
8. [Azure MCP and sandbox](#azure-mcp-and-sandbox)
9. [Testing the security gateway](#testing-the-security-gateway)
10. [Caching and cost optimization](#caching-and-cost-optimization)
11. [Troubleshooting](#troubleshooting)
12. [Security guidelines](#security-guidelines)
13. [Development roadmap](#development-roadmap)
14. [Contributing and license](#contributing-and-license)

## What problem does AIRLOCK solve?

AI agents can use MCP tools to read source code, inspect cloud resources, update configurations, and potentially perform destructive operations. **Having an API key or being authenticated does not make every agent action safe.** A malicious GitHub issue, prompt injection, mistaken reasoning, or excessive permissions can lead to unintended tool calls.

AIRLOCK aims to create a security boundary **between the agent's proposed action and the system that executes it**.

- **ALLOW** — verified, policy-permitted action executes.
- **REVIEW** — action pauses until an authorized person approves or denies it.
- **DENY** — prohibited action is blocked before reaching the downstream MCP tool.

The model can assist with understanding risk, but **the backend policy engine must make the final access-control decision**.

## Features and development status

| Component | Purpose | Status to verify in code |
| --- | --- | --- |
| Gemini AI assistant | General conversations, coding help, and tool selection | Earlier working prototype |
| Web interface | Chat and security dashboard | Prototype exists; current build unverified |
| Independent MCP gateway | Intercept actual tool calls | Architecture defined; verify implementation |
| ALLOW / REVIEW / DENY | Policy-based decisions and human review | Verify backend enforcement |
| GitHub MCP | Real repository, issue, and PR access | Integration designed; verify connection |
| Azure MCP | Authorized cloud resource access | Integration designed; verify connection |
| Local attack sandbox | Disposable MCP tools and synthetic resources | Verify isolated runtime and tests |
| Authentication and audit | Roles, sessions, approvals, logs | Verify active endpoints and persistence |
| Policy Studio and scanner | Configurable rules and file analysis | Verify implementation |
| Intelligent cache and Efficiency Engine | Reduce eligible repeated Gemini calls, measure token costs | Verify telemetry and cache behavior |

**Before a demo:** update these statuses according to actual test results; do not imply that a designed feature is already implemented.

## How AIRLOCK works

```text
User / Developer / Security Administrator
                   |
             AIRLOCK Website
                   |
            Gemini AI Assistant
                   |
          +--------+---------+
          |                  |
    Normal question    Proposed MCP tool call
          |                  |
     AI response        AIRLOCK Gateway
                             |
                    Identity + Policy + Risk
                             |
                  +----------+----------+
                  |          |          |
                ALLOW      REVIEW      DENY
                  |          |          |
                Execute   Human gate   Block
                  |
                MCP Client
                  |
        +---------+----------+-----------+
        |                    |           |
     GitHub MCP           Azure MCP   Local MCP
```

**Example:** “Give me a to-do list” is a normal Gemini response; no MCP tool is necessary. “Read an issue in my GitHub repository” requires an authorized MCP read. “Delete a protected resource” must be assessed by the independent security rules before execution.

## Requirements

Install what your checkout actually uses:

- **Python 3** and `pip` (the earlier backend was Python-based).
- **Git**, to clone the repository.
- **A Gemini API key**, to use AI chat.
- **Node.js and npm**, *only if* a `package.json`-based frontend exists.
- **Docker Desktop**, *only if* you run containerized MCP integrations or an isolated sandbox.
- **A GitHub account and suitably scoped token**, *only if* enabling GitHub MCP.
- **An Azure test identity/subscription**, *only if* enabling Azure MCP.

For Windows, PowerShell is sufficient for the basic Python setup. WSL is optional unless required by a particular integration.

## Quick start — Windows PowerShell

### 1. Obtain the source code

Replace the placeholder with your actual AIRLOCK GitHub repository URL:

```powershell
git clone <YOUR_AIRLOCK_REPOSITORY_URL>
cd <YOUR_REPOSITORY_FOLDER>
```

Already have the source on your PC? Open PowerShell in that directory instead.

### 2. Check the project's real entry points

The repository was not attached when this README was prepared. Find its actual configuration before running anything:

```powershell
Get-ChildItem -Name
Get-ChildItem -Recurse -File -Include server.py,main.py,app.py,requirements.txt,pyproject.toml,package.json,.env.example | Select-Object FullName
```

Typical meanings:

| File | Meaning |
| --- | --- |
| `server.py` | Possible Python application entry point (used in the earlier Sentinel prototype) |
| `requirements.txt` | Python dependencies |
| `pyproject.toml` | Modern Python dependency/build configuration |
| `package.json` | JavaScript frontend and its run scripts |
| `.env.example` | Required environment configuration template |
| `docker-compose.yml` or `compose.yaml` | Optional container stack |

**Use the commands corresponding to files that actually exist.**

### 3. Create a Python virtual environment

From the Python backend directory, or repository root if that is where its dependencies live:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
```

If PowerShell blocks activation, you can run the Python executable directly from `.venv\Scripts\python.exe`, or temporarily allow scripts in the current process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 4. Install Python dependencies

If the backend has `requirements.txt`:

```powershell
python -m pip install -r requirements.txt
```

If it uses `pyproject.toml`, use its documented package manager/build instructions; do not mix managers blindly.

The official current Gemini Python package is `google-genai`, but prefer the versions pinned by the project. **Do not install a random replacement for the existing backend's dependency setup.**

### 5. Configure the Gemini API key

Look for the sample environment file:

```powershell
Get-ChildItem -Recurse -Force -Filter .env.example
```

If your backend has `.env.example`, copy it into the same expected configuration directory:

```powershell
Copy-Item .env.example .env
```

Then open `.env` and set the existing project's required key:

```dotenv
GEMINI_API_KEY=YOUR_GEMINI_API_KEY_HERE
```

If the project uses other variables (database URLs, ports, model IDs, GitHub credentials), follow its actual `.env.example`.

**Important:** `.env` must be placed where the backend loads it. A common failure is starting Python in one directory while the app searches for `.env` in another.

Check that `.env` is ignored by Git:

```powershell
git check-ignore .env
```

If there is no result, add `.env` and other secret files to `.gitignore` before committing.

### 6. Start the Python backend

In the earlier Sentinel prototype, the backend started with:

```powershell
python server.py
```

That prototype reported its web dashboard at:

**http://localhost:8080**

Use this command and URL **only if your current AIRLOCK checkout still has that entry point and port**.

Other typical Python entry points require different commands, for example `uvicorn package.main:app --reload` for a FastAPI application. The actual module path and port must be determined from your source, not guessed.

Keep the backend terminal open while using the app.

### 7. Start the frontend (if separate)

Only follow this section if the repo includes a frontend folder with `package.json`.

From that folder:

```powershell
npm install
npm run
```

`npm run` lists available scripts. If the repository defines a `dev` script, start it with:

```powershell
npm run dev
```

Open the **local URL printed by the frontend terminal**. Don't assume it uses the same port as the backend.

For a production build, use the actual `build` and `start` scripts defined in that `package.json`.

### 8. Verify AIRLOCK is running

- The backend process starts without an exception.
- The browser can load the frontend or backend-served page.
- A normal Gemini prompt returns a response.
- The interface correctly shows which MCP servers are connected, disconnected, or unconfigured.
- Security features are shown as operational only when backed by working API routes and tested behavior.

**First test prompt:**

> Create a simple five-item to-do list for tomorrow.

This checks the assistant without requiring any MCP integrations.

## How to use AIRLOCK

### As a normal user

1. Sign in **if authentication is implemented and configured**. Never assume a default admin password exists.
2. Open the **AI Assistant**.
3. Type a general question, ask for coding help, or request a to-do list.
4. When requesting an external tool action, review the status presented by AIRLOCK.
5. For an operation requiring approval, wait for an authorized approver; do not bypass the gate.

### As a security administrator (if implemented)

1. Open the **Command Center** to inspect request and connection status.
2. Open **Access Control** to view ALLOW / REVIEW / DENY results.
3. Open **Pending Approvals** to inspect and decide eligible requests.
4. Open **Policy Studio** to review or test access rules.
5. Open **Audit Timeline** to follow requests, decisions, and actual execution outcomes.
6. Open **Attack Lab** to run synthetic scenarios in a resettable environment.
7. Open **Efficiency Engine** to inspect token and caching statistics where measured.

### Example prompts

| Prompt | Expected behavior if module is working |
| --- | --- |
| “Explain MCP in simple terms.” | Normal Gemini response |
| “Make a revision schedule for tomorrow.” | Normal AI response; potentially cacheable if eligible |
| “Read an issue in my approved GitHub repo.” | Authorize then use GitHub MCP |
| “Update a staging configuration.” | Check policy, possibly require approval |
| “Delete a protected demo database.” | Deny under configured policy |
| “Inspect this file for exposed secrets.” | Apply actual configured scanning controls |

## GitHub MCP setup

The supported official GitHub MCP server lives at:

**https://github.com/github/github-mcp-server**

It can expose GitHub repository content, issues, pull requests, and other supported tools. Its available capabilities depend on the selected toolsets and GitHub permissions.

### Recommended safe starting setup

1. Install Docker Desktop and confirm it is running.
2. Create a **fine-grained GitHub token** limited to repositories you intend to use. Prefer read-only permissions initially.
3. Configure the AIRLOCK backend's GitHub MCP connector to launch the official server using MCP `stdio`, or use an implemented remote MCP connection.
4. Start in GitHub MCP **read-only mode**.
5. Verify the connector discovers real tools and can execute an authorized read.
6. Verify AIRLOCK's gateway receives the proposed tool call **before** the GitHub MCP server.

The official local image is `ghcr.io/github/github-mcp-server`. The documented options include `GITHUB_PERSONAL_ACCESS_TOKEN`, `GITHUB_READ_ONLY=1`, and `GITHUB_TOOLSETS`.

**Illustrative PowerShell setup for a local test session:**

```powershell
$secureToken = Read-Host "GitHub token" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
try {
    $env:GITHUB_PERSONAL_ACCESS_TOKEN = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}
docker run -i --rm `
  -e GITHUB_PERSONAL_ACCESS_TOKEN `
  -e GITHUB_READ_ONLY=1 `
  -e GITHUB_TOOLSETS=repos,issues,pull_requests `
  ghcr.io/github/github-mcp-server
Remove-Item Env:GITHUB_PERSONAL_ACCESS_TOKEN
```

> The Docker process speaks MCP over standard input/output; **it is not a website**. It typically waits for a compatible MCP client. AIRLOCK's MCP client should manage this process in the actual integration. The example is not a substitute for implementing the Python MCP client and gateway routing.

**Never run with broad write permissions against your main repositories.** For approval/denial demonstrations, use a separate disposable repository and a separately scoped write-capable test identity.

A secure connector should report actual connected/disconnected status, discovered tool names, and permission scope. Starting Docker alone does not prove AIRLOCK is enforcing tool requests.

## Azure MCP and sandbox

### Azure MCP (optional / if implemented)

- Authenticate with a dedicated test identity.
- Grant the minimum Azure RBAC permissions required.
- Start with read-only queries against development resources.
- Use the actual Azure MCP server's documented installation, transport, and tool names.
- Route all agent-proposed Azure tool actions through AIRLOCK policies.
- Keep destructive demonstrations out of production accounts.

**Do not interpret the existence of an Azure logo or connection card as proof of live integration.**

### Local attack sandbox (if implemented)

The sandbox should contain disposable, synthetic data rather than real infrastructure. Example scenarios:

1. **Protected database deletion** — AIRLOCK denies the attempted downstream tool call.
2. **Prompt injection** — suspicious instructions in a synthetic issue attempt to redirect the agent.
3. **Synthetic secret transfer** — a fake API key is sent toward an unauthorized destination and blocked.
4. **Human approval** — a staging update waits for an approver.

To demonstrate meaningful enforcement, compare the sandbox resource state and downstream tool execution counter **before and after** the attempted action. A blocked request should not execute or mutate protected resources.

## Testing the security gateway

If the repository uses `pytest`, run the test suite from the documented backend directory:

```powershell
python -m pytest
```

If there is a dedicated sandbox or integration test script, use the exact repository command. No specific suite name can be verified from the available materials.

The strongest demo checks are:

| Test | Expected evidence |
| --- | --- |
| Normal chat | AI response returned without an MCP tool invocation |
| Authorized MCP read | Downstream read executed and response returned |
| Denied MCP call | Policy denial recorded; downstream invocation count unchanged |
| Approval gate | No execution until an authorized approval is recorded |
| Approval replay | Same approval cannot execute a tool twice |
| Prompt injection attempt | Unauthorized proposed action denied even if content classification misses it |
| Audit trail | Correlated events for caller, policy, decision, and outcome |
| Sandbox reset | Synthetic resources restored to original state |

Do not mark tests as passed until actually run.

## Caching and cost optimization

AIRLOCK's Efficiency Engine is designed to minimize unnecessary Gemini calls while maintaining privacy and access controls.

- **Response caching:** A repeated eligible, static, non-sensitive request can reuse a valid answer without another model call.
- **Provider context caching:** May reduce costs for repeated reusable input context on supported Gemini APIs/models.
- **Model routing:** Can choose appropriate models for simple versus complex work.
- **Context optimization:** Avoids sending irrelevant history or entire repositories when smaller relevant inputs suffice.

**Never cache tool authorization approvals or replay tool executions.** Private repository answers must remain scoped to authorized users and tenants.

When implemented, the dashboard should distinguish **actual provider token usage**, **estimated cost avoided**, and **forecast savings**. Projected savings are not measured savings.

## Troubleshooting

### `GEMINI_API_KEY is missing from .env`

- Check that the file is named exactly `.env`, not `.env.txt`.
- Check that it contains `GEMINI_API_KEY=...` with a valid value.
- Check the backend's dotenv-loading path.
- Start Python from the correct directory or configure an explicit `.env` path.
- Restart the backend after changing environment variables.

### `[Errno 11001] getaddrinfo failed`

This usually indicates a DNS/network name-resolution issue. Check your connection, firewall, proxy, VPN, and the API endpoint. It is not proof that the API key itself is invalid.

### `Failed to fetch` in the frontend

- Verify the backend is running and on the expected port.
- Check the frontend's configured API base URL.
- Open browser developer tools → Network to inspect the failed request.
- Check CORS, cookies/authentication, protocol mismatch, and console errors.
- Do not assume a frontend-only screenshot means login or backend auth works.

### HTTP 405 Method Not Allowed

The requested URL exists but may not accept the HTTP method being used. Compare the frontend request method (`GET`, `POST`, etc.) with the backend route definition.

### `localhost:8080` does not load

The earlier Sentinel prototype used this address; your current AIRLOCK checkout may use another port.

```powershell
netstat -ano | findstr :8080
```

Check terminal errors and any configured host/port values. The app may expose only APIs at the root URL.

### PowerShell cannot activate `.venv`

Use the process-level execution-policy command from Step 3, or run `.venv\Scripts\python.exe` directly.

### MCP server starts but no GitHub data appears

- Confirm the MCP client actually connected and performed initialization.
- Check token permission scope and selected toolsets.
- Confirm the repository is accessible to the connected identity.
- Inspect AIRLOCK connection logs and tool discovery output.
- Remember: an MCP `stdio` server is not a browser page.

### Docker cannot connect

Check Docker Desktop is running:

```powershell
docker info
```

Then verify the image is available and inspect the container's error logs.

## Security guidelines

- Never commit `.env`, GitHub tokens, Gemini keys, Azure credentials, or production secrets.
- Use minimal GitHub and Azure permissions.
- Use disposable repositories and synthetic credentials for attack tests.
- Protect admin endpoints with backend authentication and role checks.
- Implement final ALLOW / REVIEW / DENY enforcement in backend code, not Gemini messages.
- Do not rely solely on a numeric risk score to authorize an operation.
- Do not assume prompt-injection detection catches every attempt.
- Separate live production data from the Attack Lab.
- Do not call a system “enterprise-ready” or “compliant” solely because the architecture includes security controls.

## Development roadmap

- [x] Initial Python/Gemini assistant prototype demonstrated previously.
- [ ] Verify current AIRLOCK frontend and authentication end-to-end.
- [ ] Verify independent MCP tool-call interception and fail-closed blocking.
- [ ] Validate the GitHub MCP read-only integration against an authorized repository.
- [ ] Validate Azure MCP connection using a scoped test identity.
- [ ] Demonstrate a real local sandbox denial with execution evidence.
- [ ] Complete approval workflow, policy testing, and audit records.
- [ ] Validate file security scanning and prompt-injection protections.
- [ ] Measure cache hit rates, token usage, and net operating cost.
- [ ] Add reproducible integration/load tests and deployment documentation.

Change a checkbox to complete only after it works in the current repository and has been tested.

## Contributing and license

Contributions, reproducible bug reports, documentation improvements, and safe demonstration scenarios are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Keep secrets and real production data out of tests.
4. Run the project's documented tests.
5. Open a pull request explaining your changes and security implications.

**License:** Check the repository's actual `LICENSE` file before stating a license. If there is no license file, choose and add one before advertising AIRLOCK as open source.

---

**AIRLOCK — AI Moves. AIRLOCK Decides.**

> To replace the conditional setup instructions with exact, verified commands, provide the GitHub URL to the AIRLOCK source repository or upload its `README.md`, `requirements.txt` / `pyproject.toml`, `package.json`, and backend startup files.
