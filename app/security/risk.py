"""Transparent risk scoring that informs operators but never grants access."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RiskAssessment:
    """A reproducible assessment of one requested tool operation."""

    score: int
    category: str
    factors: list[str]
    explanation: str


READ_ONLY_TOOLS = {
    # GitHub MCP read tools
    "get_me",
    "search_repositories",
    "get_file_contents",
    "list_commits",
    "get_commit",
    "list_branches",
    "list_tags",
    "list_issues",
    "search_issues",
    "issue_read",
    "list_pull_requests",
    "search_pull_requests",
    "pull_request_read",
    "list_workflows",
    "list_workflow_runs",
    "list_dependabot_alerts",
    "list_code_scanning_alerts",
    # Legacy / local fixture read tools
    "list_resources",
    "list_local_repository_files",
    "read_local_repository_file",
    "list_synthetic_azure_resources",
    "get_synthetic_azure_resource",
}

DESTRUCTIVE_TOOL_MARKERS = ("delete", "destroy", "drop", "purge")


def assess_tool_request(tool_name: str, arguments: dict[str, Any]) -> RiskAssessment:
    """Score known characteristics only; authorization remains a separate decision."""
    score = 0
    factors: list[str] = []
    lowered_name = tool_name.lower()
    serialized_arguments = " ".join(str(value).lower() for value in arguments.values())

    if tool_name in READ_ONLY_TOOLS:
        score += 10
        factors.append("read_only_operation")
    elif any(marker in lowered_name for marker in DESTRUCTIVE_TOOL_MARKERS):
        score += 80
        factors.append("destructive_operation")
    else:
        score += 35
        factors.append("state_changing_or_unknown_operation")

    if "prod" in serialized_arguments or "production" in serialized_arguments:
        score += 25
        factors.append("production_target_indicator")

    if ".." in serialized_arguments or "/etc/" in serialized_arguments or "\\etc\\" in serialized_arguments:
        score += 70
        factors.append("path_traversal_attempt")

    if "secret" in lowered_name or "secret" in serialized_arguments or "token" in serialized_arguments:
        score += 50
        factors.append("confidential_credential_access")

    # Protected branch target detection
    if "main" in serialized_arguments or "master" in serialized_arguments:
        if tool_name not in READ_ONLY_TOOLS:
            score += 45
            factors.append("protected_branch_target")

    if "branch" in lowered_name or "vnet" in lowered_name or "deprovision" in lowered_name:
        score += 40
        factors.append("infrastructure_or_repo_tampering")

    # Workflow modification indicator
    if "workflow" in serialized_arguments or ".github" in serialized_arguments:
        if tool_name not in READ_ONLY_TOOLS:
            score += 35
            factors.append("ci_cd_workflow_modification")

    score = min(score, 100)
    category = "High" if score >= 70 else "Medium" if score >= 30 else "Low"
    return RiskAssessment(
        score=score,
        category=category,
        factors=factors,
        explanation=f"{category} risk ({score}/100): " + ", ".join(factors),
    )
