# AIRLOCK architecture

AIRLOCK — Zero-Trust AI Security Gateway is a local MCP security boundary for
autonomous AI agents. Its product promise is: **AI Moves. AIRLOCK Decides.**

## Current implementation

The Python/FastAPI management application serves the static web console and
exposes authenticated management endpoints in the desktop build. Gemini is
used only to propose conversational replies and function calls; it does not
receive upstream MCP credentials.

Every managed tool call follows this path:

```text
Gemini or MCP client -> AIRLOCK gateway -> policy/risk/integrity checks
                                               | allow / review / deny
                                               v
                                      reviewed synthetic MCP upstream
```

`gateway_server.py` discovers approved upstream tools, validates their
fingerprints, evaluates local JSON policy, records SQLite audit evidence, and
blocks a call before forwarding when checks fail. Response inspection is also
performed before upstream content is returned to the client. The local MCP
server provides only synthetic Azure-style resources for safe demonstrations.

## Target integration boundary

GitHub, Azure, and other MCP servers must be added as reviewed upstreams of the
same AIRLOCK gateway. Each integration needs schema fingerprint approval,
least-privilege credentials held outside the model context, policy coverage,
audit correlation, and an execution counter or trace. Direct model-to-tool
connectivity is outside the AIRLOCK trust boundary and is not an equivalent
implementation.

## Compatibility

Existing `SENTRY_X_*` environment variables, SQLite filenames, and legacy
launcher remain supported during migration. They are compatibility interfaces,
not user-facing AIRLOCK branding.
