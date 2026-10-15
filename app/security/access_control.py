"""Deterministic three-state access decisions for protected operations.

This module deliberately accepts no model-supplied decision or risk score. It
is usable by an MCP router before a downstream connection is created.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Any

from app.security.risk import RiskAssessment, assess_tool_request
from app.policies.github_policy import GitHubAccessDecision, GitHubSecurityPolicyEngine


class AccessDecision(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


@dataclass(frozen=True)
class AccessEvaluation:
    decision: AccessDecision
    reason: str
    matched_policies: list[str]
    risk: RiskAssessment
    execution_permitted: bool

    def public_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["decision"] = self.decision.value
        return result


_GITHUB_ENGINE = GitHubSecurityPolicyEngine()

GITHUB_TOOLS = {
    "get_me", "search_repositories", "get_file_contents", "list_commits", "get_commit",
    "list_branches", "list_tags", "list_issues", "search_issues", "issue_read",
    "list_pull_requests", "search_pull_requests", "pull_request_read", "list_workflows",
    "list_workflow_runs", "list_dependabot_alerts", "list_code_scanning_alerts",
    "create_or_update_file", "create_branch", "delete_file", "delete_repository",
    "issue_write", "add_issue_comment", "create_pull_request", "merge_pull_request"
}


def evaluate_protected_operation(tool_name: str, arguments: dict[str, Any]) -> AccessEvaluation:
    """Evaluate known GitHub or local-demo operations, failing closed for everything else."""
    risk = assess_tool_request(tool_name, arguments)

    # Route GitHub tools through GitHubSecurityPolicyEngine
    if tool_name in GITHUB_TOOLS:
        gh_eval = _GITHUB_ENGINE.evaluate(tool_name, arguments)
        decision_map = {
            GitHubAccessDecision.ALLOW: AccessDecision.ALLOW,
            GitHubAccessDecision.REQUIRE_APPROVAL: AccessDecision.REQUIRE_APPROVAL,
            GitHubAccessDecision.DENY: AccessDecision.DENY,
        }
        return AccessEvaluation(
            decision=decision_map[gh_eval.decision],
            reason=gh_eval.reason,
            matched_policies=gh_eval.matched_policies,
            risk=risk,
            execution_permitted=gh_eval.execution_permitted,
        )

    serialized = " ".join(str(value).lower() for value in arguments.values())
    destructive = any(word in tool_name.lower() for word in ("delete", "destroy", "drop", "purge"))

    # Traversal detection
    if ".." in serialized or "/etc/" in serialized or "\\etc\\" in serialized:
        return AccessEvaluation(
            AccessDecision.DENY,
            "Filesystem path traversal escape attempt detected. Access outside repository fixture is denied.",
            ["WORKSPACE-BOUNDARY-001", "PATH-TRAVERSAL-DENY-004"],
            risk,
            False,
        )

    # Credential exfiltration detection
    if "secret" in tool_name.lower() or "secret" in serialized or "token" in serialized:
        return AccessEvaluation(
            AccessDecision.DENY,
            "Confidential credential exfiltration prevented by DLP and Zero-Trust egress policy.",
            ["DLP-SECRET-TRANSFER-001", "CREDENTIAL-PROTECTION-005"],
            risk,
            False,
        )

    # GitHub repository branch tampering
    if "branch" in tool_name.lower() or ("repo" in tool_name.lower() and ("main" in serialized or "master" in serialized or "delete" in tool_name.lower() or "modify" in tool_name.lower())):
        return AccessEvaluation(
            AccessDecision.DENY,
            "GitHub branch tampering prohibited. Protected main branch cannot be modified or deleted by agent.",
            ["BRANCH-PROTECTION-001", "GITHUB-WRITE-RESTRICTED-002"],
            risk,
            False,
        )

    # Azure virtual network and infrastructure tampering
    if "vnet" in tool_name.lower() or ("azure" in tool_name.lower() and ("vnet" in serialized or "deprovision" in tool_name.lower() or "network" in serialized)):
        return AccessEvaluation(
            AccessDecision.DENY,
            "Azure cloud infrastructure tampering prohibited. Virtual network deprovisioning requires Enterprise Cloud Admin credentials.",
            ["AZURE-RBAC-RESTRICTED-001", "INFRASTRUCTURE-TAMPER-003"],
            risk,
            False,
        )

    if destructive or "production" in serialized or "prod-" in serialized:
        return AccessEvaluation(
            AccessDecision.DENY,
            "Destructive or production-targeted operations are hard denied in the local policy.",
            ["ZERO-TRUST-DEFAULT-DENY-003", "DESTRUCTIVE-ACTION-002"],
            risk,
            False,
        )

    if tool_name == "restart_vm":
        return AccessEvaluation(
            AccessDecision.REQUIRE_APPROVAL,
            "State-changing development operations require a short-lived, bound approval.",
            ["CHANGE-REVIEW-001", "SEPARATION-OF-DUTIES-002"],
            risk,
            False,
        )

    return AccessEvaluation(
        AccessDecision.ALLOW,
        "Read-only synthetic fixture operation allowed by default local demo policy.",
        ["READ-ONLY-FIXTURE-001"],
        risk,
        True,
    )
