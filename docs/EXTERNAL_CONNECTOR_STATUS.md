# External MCP connector status

This document records verified connector research without claiming an external
server is connected through AIRLOCK.

## GitHub MCP Server

The official `github/github-mcp-server` repository was inspected at a local
shallow checkout. Its documented local transport is stdio, either through the
official `ghcr.io/github/github-mcp-server` Docker image or a Go-built binary.
The documentation supports a strict `--read-only` mode and tool/toolset
allowlisting. Its documented credential choices are in-memory OAuth login or
`GITHUB_PERSONAL_ACCESS_TOKEN`; a read-only, fine-grained token should be used
for a dedicated disposable test repository.

Current blocker: this development environment has no Docker executable, no Go
toolchain, and no `GITHUB_PERSONAL_ACCESS_TOKEN`. Therefore AIRLOCK has not
started, discovered, approved, or forwarded any GitHub MCP tool. No mock has
been substituted.

When prerequisites are available, the required sequence is:

1. Start the official server with read-only mode and a narrow tool allowlist.
2. Discover its real tool names and schemas over MCP before adding policy.
3. Record reviewed fingerprints in AIRLOCK.
4. Permit only confirmed read tools and only the dedicated test repository.
5. Prove a denied write operation is not forwarded.

## Microsoft Azure MCP

The `microsoft/mcp` repository was inspected from its Git object database. A
normal Windows checkout could not complete because one repository path exceeded
the Windows filename-length limit; this does not establish a usable server.
The repository contains multiple MCP products, so no Azure tool names or
transport are assumed here.

Current blockers: no Azure credentials/subscription are configured and no
specific Azure MCP server has been installed, started, or discovered. The
existing `synthetic_azure_inventory.json` is local fictional fixture data only;
it is not an Azure connector.

For a later sandbox integration, use an Entra identity with the least Azure RBAC
needed for read-only inspection, discover the actual server tools first, map
them to policy capabilities, fingerprint them, and test only against a
dedicated non-production subscription.

## Security rule

Neither connector may be made available directly to Gemini. Once configured,
each must be an upstream of the same AIRLOCK gateway path that performs policy
validation, fingerprint verification, response inspection, risk recording, and
SQLite auditing.
