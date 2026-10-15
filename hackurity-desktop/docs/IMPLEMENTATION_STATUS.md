# AIRLOCK desktop implementation status

## Implemented in this folder

- A real local MCP gateway that evaluates deterministic policy before opening an
  upstream execution session. Denied calls are recorded with
  `upstream_executed=false` and do not reach the synthetic MCP server.
- A premium, responsive security console whose operational telemetry comes from
  the management API, rather than fabricated browser data.
- Three deterministic outcomes for the protected-operation simulator: allow,
  require approval, and deny. A destructive or production-targeted action is a
  hard deny and never becomes approvable.
- SQLite-backed short-lived approval records that bind to a canonical tool and
  argument hash, expire, enforce separation of duties, and can be consumed
  exactly once.
- Argon2id password hashes, opaque HTTP-only sessions, 8-hour expiry, logout
  revocation, and a five-failure account lockout. No account or password is
  provisioned automatically.
- Existing local synthetic MCP integration, audit records, schema-fingerprint
  checks, and response-instruction inspection are retained.
- Policy Studio exposes backend dry-runs, Attack Simulation Lab renders a
  before/after synthetic comparison, File Security Scanner performs bounded
  non-executing checks, Identity & Access shows auth events, and Incident
  Reports exports the currently verified event set as JSON.

## Run locally

```powershell
cd .\hackurity-desktop
..\.venv\Scripts\python.exe -m pip install -r requirements.txt
..\.venv\Scripts\python.exe .\scripts\provision_user.py security-admin security_admin
..\.venv\Scripts\python.exe -m app.api.run_management
```

Open `http://127.0.0.1:8000`. The startup sequence leads to the login portal;
provision a local account before accessing the console.

## Deliberately incomplete

- GitHub and Azure remain safe local fixtures; no production cloud connector is
  claimed or invoked.
- Approval consumption is exposed as an authorization boundary, but it does not
  yet call the MCP executor after re-evaluation. This avoids presenting a
  simulated approval as a real external operation.
- User management, password reset, CSRF origin enforcement, policy writing,
  real-time streaming, and PDF/compliance export are not implemented in this
  vertical slice. JSON incident export and bounded file scanning are local
  demonstration features, not malware detection or a compliance claim.
- The local HTTP development server sets an HTTP-only, SameSite=Strict cookie
  without `Secure`; deploy behind TLS and set `Secure` before any non-local use.
