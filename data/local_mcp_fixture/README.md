# Local MCP data fixture

This directory is a safe, local-only data source for the AIRLOCK MCP server.

- `synthetic_azure_inventory.json` contains fictional Azure-style metadata. It
  has no credentials and is never sent to Azure.
- `github-gitignore/` is a shallow clone of GitHub's public, CC0 1.0-licensed
  `github/gitignore` repository. It is ignored by this project's Git rules and
  can be recreated with `scripts/setup_local_data.ps1`.

The MCP server exposes read-only repository and inventory tools. The existing
restart/delete tools still affect only their separate in-memory synthetic store.
