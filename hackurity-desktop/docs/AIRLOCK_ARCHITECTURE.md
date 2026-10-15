# AIRLOCK architecture

AIRLOCK — Zero-Trust AI Security Gateway is the rebranded MCP security boundary
for autonomous AI agents: **AI Moves. AIRLOCK Decides.**

Gemini may propose a tool call, but AIRLOCK independently validates the tool
schema and fingerprint, evaluates policy and risk, records audit evidence, and
chooses ALLOW, REVIEW, or DENY before any upstream MCP execution. The included
upstream is synthetic and local-only; external GitHub and Azure integrations
must use this same gateway boundary rather than direct model access.

Legacy `SENTRY_X_*` environment variables and SQLite paths are retained solely
for migration compatibility.
