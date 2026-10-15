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
    if "secret" in lowered_name or "secret" in serialized_arguments:
        score += 50
        factors.append("confidential_credential_access")
    if tool_name not in READ_ONLY_TOOLS and tool_name != "restart_vm":
        score += 15
        factors.append("unrecognized_capability")

    score = min(score, 100)
    category = "High" if score >= 70 else "Medium" if score >= 30 else "Low"
    return RiskAssessment(
        score=score,
        category=category,
        factors=factors,
        explanation=f"{category} risk ({score}/100): " + ", ".join(factors),
    )
