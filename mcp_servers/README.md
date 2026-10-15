# Local MCP test servers

`local_server.py` exposes three tools over real MCP stdio transport:

- `list_resources` lists only in-memory demonstration resources.
- `restart_vm` changes the status of a synthetic VM in memory.
- `delete_resource` removes only a synthetic resource from memory.

Every server process starts with a fresh store, and no tool accesses cloud
accounts, production resources, files, shells, or real infrastructure.
