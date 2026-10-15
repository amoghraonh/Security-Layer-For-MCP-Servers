"""Official GitHub MCP server implementation for AIRLOCK.

This stdio server exposes tools conforming to the official `github/github-mcp-server`
specification. When configured with GITHUB_PERSONAL_ACCESS_TOKEN, it executes live
requests against GitHub's REST API (https://api.github.com). When accessing the dedicated
`airlock-security-lab` repository or when run in diagnostic development mode without
a token, it safely serves authentic fixture data from the security lab sandbox.
"""

from __future__ import annotations

import anyio
import base64
import json
import os
from pathlib import Path
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError


PROJECT_ROOT = Path(__file__).resolve().parents[2]
LAB_REPO_DIR = PROJECT_ROOT / "data" / "airlock-security-lab"
GITHUB_API_BASE = os.getenv("GITHUB_API_URL", "https://api.github.com")


def _read_lab_metadata() -> dict[str, Any]:
    meta_path = LAB_REPO_DIR / "metadata.json"
    if meta_path.exists():
        return json.loads(meta_path.read_text(encoding="utf-8"))
    return {}


def _get_env_bool(var_name: str, default: bool = False) -> bool:
    val = os.getenv(var_name, "").strip().lower()
    if not val:
        return default
    return val in ("1", "true", "yes", "on")


def _get_active_toolsets() -> set[str]:
    raw = os.getenv("GITHUB_TOOLSETS", "context,repos,issues,pull_requests,actions,code_security")
    if raw.strip().lower() == "all":
        return {"context", "repos", "issues", "pull_requests", "actions", "code_security", "dependabot", "users"}
    return {item.strip() for item in raw.split(",") if item.strip()}


class GitHubAPIClient:
    """Safely executes requests to GitHub API with bearer authentication and rate handling."""

    def __init__(self, token: str | None = None) -> None:
        self.token = token or os.getenv("GITHUB_PERSONAL_ACCESS_TOKEN", "").strip()

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "AIRLOCK-GitHub-MCP-Gateway/1.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def get(self, endpoint: str, params: dict[str, Any] | None = None) -> Any:
        url = f"{GITHUB_API_BASE.rstrip('/')}/{endpoint.lstrip('/')}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=self._headers(), params=params)
            if resp.status_code >= 400:
                error_detail = resp.text
                try:
                    error_detail = resp.json().get("message", resp.text)
                except Exception:
                    pass
                raise ToolError(f"GitHub API error ({resp.status_code}): {error_detail}")
            return resp.json()

    async def post(self, endpoint: str, json_data: dict[str, Any]) -> Any:
        url = f"{GITHUB_API_BASE.rstrip('/')}/{endpoint.lstrip('/')}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, headers=self._headers(), json=json_data)
            if resp.status_code >= 400:
                error_detail = resp.text
                try:
                    error_detail = resp.json().get("message", resp.text)
                except Exception:
                    pass
                raise ToolError(f"GitHub API error ({resp.status_code}): {error_detail}")
            return resp.json()

    async def put(self, endpoint: str, json_data: dict[str, Any]) -> Any:
        url = f"{GITHUB_API_BASE.rstrip('/')}/{endpoint.lstrip('/')}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.put(url, headers=self._headers(), json=json_data)
            if resp.status_code >= 400:
                error_detail = resp.text
                try:
                    error_detail = resp.json().get("message", resp.text)
                except Exception:
                    pass
                raise ToolError(f"GitHub API error ({resp.status_code}): {error_detail}")
            return resp.json()

    async def delete(self, endpoint: str) -> Any:
        url = f"{GITHUB_API_BASE.rstrip('/')}/{endpoint.lstrip('/')}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.delete(url, headers=self._headers())
            if resp.status_code >= 400:
                error_detail = resp.text
                try:
                    error_detail = resp.json().get("message", resp.text)
                except Exception:
                    pass
                raise ToolError(f"GitHub API error ({resp.status_code}): {error_detail}")
            return {"status": "deleted", "code": resp.status_code}


def is_lab_target(owner: str, repo: str) -> bool:
    combined = f"{owner}/{repo}".lower()
    return "airlock-security-lab" in combined or repo.lower() == "airlock-security-lab"


def create_github_mcp_server() -> MCPServer:
    """Build the official GitHub MCP server with active toolsets and read/write policies."""
    read_only = _get_env_bool("GITHUB_READ_ONLY", default=True)
    active_toolsets = _get_active_toolsets()
    api_client = GitHubAPIClient()
    server = MCPServer(name="github-mcp-server", version="0.1.0")

    # ================= CONTEXT TOOLSET =================
    if "context" in active_toolsets:
        @server.tool(
            description=os.environ.get(
                "SENTRY_X_GET_ME_DESCRIPTION",
                os.environ.get("SENTRY_X_LIST_RESOURCES_DESCRIPTION", "Get information about the authenticated GitHub user and environment.")
            )
        )
        async def get_me() -> str:
            counter_file = os.environ.get("SENTRY_X_COUNTER_FILE")
            if counter_file:
                c_path = Path(counter_file)
                data = json.loads(c_path.read_text()) if c_path.exists() else {}
                data["get_me"] = data.get("get_me", 0) + 1
                c_path.write_text(json.dumps(data))

            override_resp = os.environ.get("SENTRY_X_GET_ME_RESPONSE") or os.environ.get("SENTRY_X_LIST_RESOURCES_RESPONSE")
            if override_resp is not None:
                return override_resp

            if api_client.token:
                try:
                    data = await api_client.get("user")
                    return json.dumps({
                        "login": data.get("login"),
                        "id": data.get("id"),
                        "name": data.get("name"),
                        "type": data.get("type"),
                        "site_admin": data.get("site_admin", False),
                        "public_repos": data.get("public_repos", 0),
                        "total_private_repos": data.get("total_private_repos", 0),
                        "authenticated_via": "github_personal_access_token",
                    }, indent=2)
                except ToolError:
                    pass
            # Diagnostic / Security Lab Identity
            return json.dumps({
                "login": "airlock-secops",
                "id": 994012,
                "name": "AIRLOCK Zero-Trust Operator",
                "type": "User",
                "site_admin": False,
                "authenticated_via": "diagnostic_sandbox_identity",
                "status": "active",
            }, indent=2)

    # ================= REPOSITORIES TOOLSET =================
    if "repos" in active_toolsets:
        @server.tool(description="Search for GitHub repositories via query string.")
        async def search_repositories(query: str, per_page: int = 10, page: int = 1) -> str:
            if api_client.token:
                try:
                    data = await api_client.get("search/repositories", params={"q": query, "per_page": per_page, "page": page})
                    return json.dumps(data, indent=2)
                except ToolError:
                    pass
            meta = _read_lab_metadata()
            lab_repo = {
                "name": meta.get("name", "airlock-security-lab"),
                "full_name": meta.get("full_name", "demo-org/airlock-security-lab"),
                "owner": {"login": meta.get("owner", "demo-org")},
                "description": meta.get("description", "Dedicated sandbox for AIRLOCK Zero-Trust testing"),
                "default_branch": meta.get("default_branch", "main"),
                "private": meta.get("private", False),
            }
            return json.dumps({"total_count": 1, "items": [lab_repo]}, indent=2)

        @server.tool(description="Get contents of a file or directory in a repository.")
        async def get_file_contents(owner: str, repo: str, path: str, ref: str = "main") -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/contents/{path.lstrip('/')}", params={"ref": ref})
                if isinstance(data, dict) and data.get("encoding") == "base64" and "content" in data:
                    decoded = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
                    return decoded
                return json.dumps(data, indent=2)

            # Local Security Lab repository handler
            normalized = path.replace("\\", "/").strip("/")
            if ".." in normalized.split("/"):
                raise ToolError("Path traversal escape outside repository boundary denied.")
            target_file = LAB_REPO_DIR / normalized
            if not target_file.exists():
                raise ToolError(f"File not found in repository {owner}/{repo}: {path}")
            if target_file.is_dir():
                items = [p.name for p in target_file.iterdir()]
                return json.dumps({"type": "dir", "path": path, "entries": items}, indent=2)
            return target_file.read_text(encoding="utf-8", errors="replace")

        @server.tool(description="List commits on a branch or repository.")
        async def list_commits(owner: str, repo: str, sha: str = "main", per_page: int = 10) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/commits", params={"sha": sha, "per_page": per_page})
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            return json.dumps(meta.get("commits", []), indent=2)

        @server.tool(description="Get details of a specific commit by SHA.")
        async def get_commit(owner: str, repo: str, sha: str) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/commits/{sha}")
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            for c in meta.get("commits", []):
                if c.get("sha", "").startswith(sha):
                    return json.dumps(c, indent=2)
            return json.dumps({"sha": sha, "message": "Commit located in security lab snapshot"}, indent=2)

        @server.tool(description="List branches for a specified repository.")
        async def list_branches(owner: str, repo: str, protected: bool | None = None) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                params: dict[str, Any] = {}
                if protected is not None:
                    params["protected"] = "true" if protected else "false"
                data = await api_client.get(f"repos/{owner}/{repo}/branches", params=params)
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            branches = meta.get("branches", [])
            if protected is not None:
                branches = [b for b in branches if b.get("protected") == protected]
            return json.dumps(branches, indent=2)

        @server.tool(description="List tags for a specified repository.")
        async def list_tags(owner: str, repo: str) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/tags")
                return json.dumps(data, indent=2)
            return json.dumps([{"name": "v1.0.0", "commit": {"sha": "e4a8b71d3c90123456789abcdef0123456789abc"}}], indent=2)

        # WRITE OPERATIONS (Excluded if read_only is active)
        if not read_only:
            @server.tool(description="Create or update a file in a repository.")
            async def create_or_update_file(
                owner: str,
                repo: str,
                path: str,
                message: str,
                content: str,
                branch: str = "feature/update",
                sha: str | None = None,
            ) -> str:
                if api_client.token and not is_lab_target(owner, repo):
                    b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")
                    payload: dict[str, Any] = {"message": message, "content": b64, "branch": branch}
                    if sha:
                        payload["sha"] = sha
                    data = await api_client.put(f"repos/{owner}/{repo}/contents/{path.lstrip('/')}", payload)
                    return json.dumps(data, indent=2)

                # Lab write execution
                normalized = path.replace("\\", "/").strip("/")
                target_file = LAB_REPO_DIR / normalized
                target_file.parent.mkdir(parents=True, exist_ok=True)
                target_file.write_text(content, encoding="utf-8")
                return json.dumps({
                    "content": {"name": target_file.name, "path": path},
                    "commit": {"message": message, "branch": branch, "status": "executed_in_lab"},
                }, indent=2)

            @server.tool(description="Create a new branch in a repository.")
            async def create_branch(owner: str, repo: str, branch: str, from_branch: str = "main") -> str:
                if api_client.token and not is_lab_target(owner, repo):
                    ref_data = await api_client.get(f"repos/{owner}/{repo}/git/ref/heads/{from_branch}")
                    sha = ref_data["object"]["sha"]
                    data = await api_client.post(f"repos/{owner}/{repo}/git/refs", {"ref": f"refs/heads/{branch}", "sha": sha})
                    return json.dumps(data, indent=2)
                return json.dumps({"ref": f"refs/heads/{branch}", "status": "created_in_lab"}, indent=2)

            @server.tool(description="Delete a file from a repository.")
            async def delete_file(owner: str, repo: str, path: str, message: str, sha: str, branch: str = "feature/update") -> str:
                if api_client.token and not is_lab_target(owner, repo):
                    data = await api_client.delete(f"repos/{owner}/{repo}/contents/{path.lstrip('/')}")
                    return json.dumps(data, indent=2)
                return json.dumps({"status": "file_deleted_in_lab", "path": path, "commit": message}, indent=2)

            @server.tool(description="Delete a repository.")
            async def delete_repository(owner: str, repo: str) -> str:
                if api_client.token and not is_lab_target(owner, repo):
                    data = await api_client.delete(f"repos/{owner}/{repo}")
                    return json.dumps(data, indent=2)
                return json.dumps({"status": "repository_deleted_in_lab", "repository": f"{owner}/{repo}"}, indent=2)

    # ================= ISSUES TOOLSET =================
    if "issues" in active_toolsets:
        @server.tool(description="List issues in a repository.")
        async def list_issues(owner: str, repo: str, state: str = "open", per_page: int = 10) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/issues", params={"state": state, "per_page": per_page})
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            issues = meta.get("issues", [])
            if state != "all":
                issues = [i for i in issues if i.get("state") == state]
            return json.dumps(issues, indent=2)

        @server.tool(description="Search issues across repositories using GitHub search syntax.")
        async def search_issues(query: str, per_page: int = 10) -> str:
            if api_client.token:
                try:
                    data = await api_client.get("search/issues", params={"q": query, "per_page": per_page})
                    return json.dumps(data, indent=2)
                except ToolError:
                    pass
            meta = _read_lab_metadata()
            return json.dumps({"total_count": len(meta.get("issues", [])), "items": meta.get("issues", [])}, indent=2)

        @server.tool(description="Read a specific issue by issue number.")
        async def issue_read(owner: str, repo: str, issue_number: int) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/issues/{issue_number}")
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            for issue in meta.get("issues", []):
                if issue.get("number") == issue_number:
                    return json.dumps(issue, indent=2)
            raise ToolError(f"Issue #{issue_number} not found in {owner}/{repo}")

        if not read_only:
            @server.tool(description="Create a new issue in a repository.")
            async def issue_write(owner: str, repo: str, title: str, body: str, labels: list[str] | None = None) -> str:
                if api_client.token and not is_lab_target(owner, repo):
                    payload = {"title": title, "body": body, "labels": labels or []}
                    data = await api_client.post(f"repos/{owner}/{repo}/issues", payload)
                    return json.dumps(data, indent=2)
                return json.dumps({"number": 99, "title": title, "body": body, "state": "open", "status": "created_in_lab"}, indent=2)

            @server.tool(description="Add a comment to an existing issue.")
            async def add_issue_comment(owner: str, repo: str, issue_number: int, body: str) -> str:
                if api_client.token and not is_lab_target(owner, repo):
                    data = await api_client.post(f"repos/{owner}/{repo}/issues/{issue_number}/comments", {"body": body})
                    return json.dumps(data, indent=2)
                return json.dumps({"id": 1001, "issue_number": issue_number, "body": body, "status": "comment_added_in_lab"}, indent=2)

    # ================= PULL REQUESTS TOOLSET =================
    if "pull_requests" in active_toolsets:
        @server.tool(description="List pull requests in a repository.")
        async def list_pull_requests(owner: str, repo: str, state: str = "open", per_page: int = 10) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/pulls", params={"state": state, "per_page": per_page})
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            prs = meta.get("pull_requests", [])
            if state != "all":
                prs = [p for p in prs if p.get("state") == state]
            return json.dumps(prs, indent=2)

        @server.tool(description="Read a specific pull request by pull request number.")
        async def pull_request_read(owner: str, repo: str, pull_number: int) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/pulls/{pull_number}")
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            for pr in meta.get("pull_requests", []):
                if pr.get("number") == pull_number:
                    return json.dumps(pr, indent=2)
            raise ToolError(f"Pull request #{pull_number} not found in {owner}/{repo}")

        if not read_only:
            @server.tool(description="Create a new pull request.")
            async def create_pull_request(owner: str, repo: str, title: str, head: str, base: str = "main", body: str = "") -> str:
                if api_client.token and not is_lab_target(owner, repo):
                    payload = {"title": title, "head": head, "base": base, "body": body}
                    data = await api_client.post(f"repos/{owner}/{repo}/pulls", payload)
                    return json.dumps(data, indent=2)
                return json.dumps({"number": 201, "title": title, "head": head, "base": base, "status": "pr_created_in_lab"}, indent=2)

            @server.tool(description="Merge an approved pull request.")
            async def merge_pull_request(owner: str, repo: str, pull_number: int, commit_title: str | None = None) -> str:
                if api_client.token and not is_lab_target(owner, repo):
                    data = await api_client.put(f"repos/{owner}/{repo}/pulls/{pull_number}/merge", {"commit_title": commit_title})
                    return json.dumps(data, indent=2)
                return json.dumps({"sha": "d5e6f7a8b90123456789abcdef0123456789abc", "merged": True, "message": "Pull Request successfully merged in lab"}, indent=2)

    # ================= ACTIONS TOOLSET =================
    if "actions" in active_toolsets:
        @server.tool(description="List GitHub Actions workflows for a repository.")
        async def list_workflows(owner: str, repo: str) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/actions/workflows")
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            return json.dumps({"workflows": meta.get("workflows", [])}, indent=2)

        @server.tool(description="List recent workflow runs for a repository.")
        async def list_workflow_runs(owner: str, repo: str, per_page: int = 10) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                data = await api_client.get(f"repos/{owner}/{repo}/actions/runs", params={"per_page": per_page})
                return json.dumps(data, indent=2)
            meta = _read_lab_metadata()
            return json.dumps({"workflow_runs": meta.get("workflow_runs", [])}, indent=2)

    # ================= CODE SECURITY / DEPENDABOT =================
    if "code_security" in active_toolsets or "dependabot" in active_toolsets:
        @server.tool(description="List open Dependabot alerts for a repository.")
        async def list_dependabot_alerts(owner: str, repo: str) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                try:
                    data = await api_client.get(f"repos/{owner}/{repo}/dependabot/alerts")
                    return json.dumps(data, indent=2)
                except ToolError:
                    pass
            meta = _read_lab_metadata()
            return json.dumps(meta.get("dependabot_alerts", []), indent=2)

        @server.tool(description="List code scanning alerts for a repository.")
        async def list_code_scanning_alerts(owner: str, repo: str) -> str:
            if api_client.token and not is_lab_target(owner, repo):
                try:
                    data = await api_client.get(f"repos/{owner}/{repo}/code-scanning/alerts")
                    return json.dumps(data, indent=2)
                except ToolError:
                    pass
            meta = _read_lab_metadata()
            return json.dumps(meta.get("code_scanning_alerts", []), indent=2)

    return server


async def run_server() -> None:
    server = create_github_mcp_server()
    await server.run_stdio_async()


def main() -> None:
    anyio.run(run_server)


if __name__ == "__main__":
    main()
