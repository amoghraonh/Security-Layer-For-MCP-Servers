"""AIRLOCK GitHub Security Policy Engine.

Enforces zero-trust policy decisions (ALLOW, REQUIRE_APPROVAL, DENY) on every
GitHub MCP tool invocation before execution.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from app.security.risk import RiskAssessment, assess_tool_request


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_GITHUB_POLICY_PATH = PROJECT_ROOT / "config" / "github_policy.json"


class GitHubAccessDecision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class GitHubPolicyEvaluation:
    decision: GitHubAccessDecision
    reason: str
    matched_policies: list[str]
    risk: RiskAssessment
    execution_permitted: bool
    requires_approval: bool
    target_repo: str | None
    target_branch: str | None

    def public_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason": self.reason,
            "matched_policies": self.matched_policies,
            "risk_score": self.risk.score,
            "risk_category": self.risk.category,
            "risk_factors": self.risk.factors,
            "execution_permitted": self.execution_permitted,
            "requires_approval": self.requires_approval,
            "target_repo": self.target_repo,
            "target_branch": self.target_branch,
        }


class GitHubSecurityPolicyEngine:
    """Evaluates GitHub MCP tool calls against strict Enterprise Zero-Trust policies."""

    def __init__(self, policy_doc: dict[str, Any] | None = None) -> None:
        self.doc = policy_doc or self._load_default()

    @classmethod
    def from_file(cls, path: Path | None = None) -> "GitHubSecurityPolicyEngine":
        p = path or DEFAULT_GITHUB_POLICY_PATH
        if p.exists():
            return cls(json.loads(p.read_text(encoding="utf-8")))
        return cls()

    def _load_default(self) -> dict[str, Any]:
        if DEFAULT_GITHUB_POLICY_PATH.exists():
            return json.loads(DEFAULT_GITHUB_POLICY_PATH.read_text(encoding="utf-8"))
        return {
            "policy_id": "AIRLOCK-GITHUB-001",
            "default_action": "deny",
            "github": {
                "allowed_repositories": ["demo-org/airlock-security-lab", "demo-org/airlock-test", "octocat/Hello-World"],
                "protected_branches": ["main", "master"],
                "protected_operations": ["delete_repository", "delete_file", "modify_security_controls"],
            },
        }

    def _allowed_repositories(self) -> set[str]:
        raw_env = os.getenv("AIRLOCK_GITHUB_ALLOWED_REPOS", "")
        env_repos = {r.strip().lower() for r in raw_env.split(",") if r.strip()}
        policy_repos = {r.lower() for r in self.doc.get("github", {}).get("allowed_repositories", [])}
        return env_repos | policy_repos | {"demo-org/airlock-security-lab", "airlock-security-lab"}

    def _protected_branches(self) -> set[str]:
        return {b.lower() for b in self.doc.get("github", {}).get("protected_branches", ["main", "master"])}

    def _protected_operations(self) -> set[str]:
        return {op.lower() for op in self.doc.get("github", {}).get("protected_operations", ["delete_repository", "delete_file"])}

    def evaluate(self, tool_name: str, arguments: dict[str, Any]) -> GitHubPolicyEvaluation:
        """Evaluate one proposed GitHub tool invocation."""
        risk = assess_tool_request(tool_name, arguments)
        serialized = " ".join(str(val).lower() for val in arguments.values())

        # Extract repository target
        owner = str(arguments.get("owner", "")).strip()
        repo = str(arguments.get("repo", "")).strip()
        target_repo = f"{owner}/{repo}" if (owner and repo) else repo or None

        # Extract branch target
        branch = str(arguments.get("branch", arguments.get("base", arguments.get("head", "")))).strip()
        target_branch = branch if branch else None

        # 1. Path traversal check
        path_arg = str(arguments.get("path", ""))
        if ".." in path_arg.replace("\\", "/").split("/") or path_arg.startswith(("/", "\\")):
            return GitHubPolicyEvaluation(
                decision=GitHubAccessDecision.DENY,
                reason="Path traversal attempt outside repository boundary denied by AIRLOCK.",
                matched_policies=["AIRLOCK-PATH-TRAVERSAL-001", "WORKSPACE-ISOLATION-002"],
                risk=risk,
                execution_permitted=False,
                requires_approval=False,
                target_repo=target_repo,
                target_branch=target_branch,
            )

        # 2. Hard-denied destructive / administrative operations
        lowered_name = tool_name.lower()
        if lowered_name in self._protected_operations() or "delete_repo" in lowered_name:
            return GitHubPolicyEvaluation(
                decision=GitHubAccessDecision.DENY,
                reason=f"Operation '{tool_name}' is classified as a hard-denied destructive action. Enterprise policy prohibits automated repository deletion.",
                matched_policies=["AIRLOCK-GITHUB-HARD-DENY-001", "DESTRUCTIVE-OPERATION-SHIELD-003"],
                risk=risk,
                execution_permitted=False,
                requires_approval=False,
                target_repo=target_repo,
                target_branch=target_branch,
            )

        # 3. Repository scope check
        if target_repo:
            normalized_repo = target_repo.lower()
            allowed = self._allowed_repositories()
            if not any(normalized_repo == a or normalized_repo.endswith("/" + a) or a.endswith("/" + normalized_repo) for a in allowed):
                return GitHubPolicyEvaluation(
                    decision=GitHubAccessDecision.DENY,
                    reason=f"Repository '{target_repo}' is not in the AIRLOCK approved repository scope. Zero-Trust access denied.",
                    matched_policies=["AIRLOCK-REPO-SCOPE-001", "ZERO-TRUST-BOUNDARY-004"],
                    risk=risk,
                    execution_permitted=False,
                    requires_approval=False,
                    target_repo=target_repo,
                    target_branch=target_branch,
                )

        # 4. Protected branch tampering check (e.g. main/master)
        is_write = lowered_name in {
            "create_or_update_file", "create_branch", "delete_file", "issue_write",
            "add_issue_comment", "create_pull_request", "merge_pull_request"
        }
        if is_write and target_branch and target_branch.lower() in self._protected_branches():
            return GitHubPolicyEvaluation(
                decision=GitHubAccessDecision.DENY,
                reason=f"Branch '{target_branch}' is an AIRLOCK-protected branch. Direct modifications or pushes by AI agents are strictly prohibited.",
                matched_policies=["AIRLOCK-BRANCH-PROTECTION-001", "PROTECTED-BRANCH-GOVERNANCE-002"],
                risk=risk,
                execution_permitted=False,
                requires_approval=False,
                target_repo=target_repo,
                target_branch=target_branch,
            )

        # 5. Credential leakage / DLP check
        if "secret" in lowered_name or "secrets/api_keys.env" in serialized or "token" in serialized:
            if is_write or "exfiltrate" in serialized or "reveal" in serialized:
                return GitHubPolicyEvaluation(
                    decision=GitHubAccessDecision.DENY,
                    reason="Potential credential exfiltration prevented by AIRLOCK DLP and Zero-Trust egress policy.",
                    matched_policies=["AIRLOCK-DLP-CREDENTIAL-001", "EGRESS-GUARD-005"],
                    risk=risk,
                    execution_permitted=False,
                    requires_approval=False,
                    target_repo=target_repo,
                    target_branch=target_branch,
                )

        # 6. Eligible write operations require human approval
        if is_write:
            return GitHubPolicyEvaluation(
                decision=GitHubAccessDecision.REQUIRE_APPROVAL,
                reason=f"GitHub write operation '{tool_name}' on repository '{target_repo or 'sandbox'}' requires administrator review before execution.",
                matched_policies=["AIRLOCK-WRITE-APPROVAL-001", "SEPARATION-OF-DUTIES-003"],
                risk=risk,
                execution_permitted=False,
                requires_approval=True,
                target_repo=target_repo,
                target_branch=target_branch,
            )

        # 7. Authorized read operations
        return GitHubPolicyEvaluation(
            decision=GitHubAccessDecision.ALLOW,
            reason=f"Authorized GitHub read operation '{tool_name}' approved by policy AIRLOCK-GITHUB-001.",
            matched_policies=["AIRLOCK-READ-PERMIT-001", "ZERO-TRUST-POLICY-VERIFIED"],
            risk=risk,
            execution_permitted=True,
            requires_approval=False,
            target_repo=target_repo,
            target_branch=target_branch,
        )
