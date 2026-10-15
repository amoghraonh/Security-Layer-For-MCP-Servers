"""Classifier that safely determines whether a prompt is eligible for response caching."""

from __future__ import annotations

import re
from typing import Any

INELIGIBLE_TOOL_MARKERS = (
    "delete", "restart", "reboot", "destroy", "drop", "purge",
    "deprovision", "create", "modify", "update", "patch", "list_resources",
    "restart_vm", "delete_resource", "read_local_repository_file",
    "list_local_repository_files", "read_synthetic_secret",
    "modify_repository_branch", "deprovision_azure_vnet",
)

INELIGIBLE_CONTENT_PATTERNS = [
    re.compile(r"(?i)\b(now|today|current time|what time|latest|live)\b"),
    re.compile(r"(?i)(?:\.\./|\.\.\\)"),
    re.compile(r"(?i)\b(api[_-]?key|password|secret|bearer\s+[a-z0-9_-]+)\b"),
    re.compile(r"(?i)\b(my\s+profile|my\s+account|personal|private\s+repo)\b"),
]

ELIGIBLE_PATTERNS = [
    re.compile(r"(?i)^(explain|what is|define|how does|compare|difference between|overview of|to-do list|checklist|best practices)\b"),
    re.compile(r"(?i)\b(zero[- ]trust|nist|owasp|architecture|concept|principle|framework|guideline|guide)\b"),
]


def classify_cache_eligibility(prompt: str, context: dict[str, Any] | None = None) -> tuple[bool, str, str]:
    """Classify prompt into (eligible: bool, category: str, reason: str).

    Never permits caching for tool execution, dynamic operations, or credential requests.
    """
    cleaned = prompt.strip().lower()

    if not cleaned:
        return False, "empty", "Empty prompts cannot be cached."

    # Tool invocation or command requests
    for marker in INELIGIBLE_TOOL_MARKERS:
        if marker in cleaned:
            return False, "tool_operation", f"Prompt requests potential tool/infrastructure operation: '{marker}'."

    # Pattern check
    for pattern in INELIGIBLE_CONTENT_PATTERNS:
        if pattern.search(cleaned):
            return False, "dynamic_or_sensitive", "Prompt contains dynamic, time-sensitive, or sensitive credentials markers."

    # Context override (e.g. if conversation has prior tool calls)
    if context and context.get("tool_execution"):
        return False, "stateful_tool", "Requests with tool execution state cannot use cached responses."

    # Educational / technical check
    for pattern in ELIGIBLE_PATTERNS:
        if pattern.search(cleaned):
            return True, "technical_explanation", "Standard technical explanation / educational concept eligible for caching."

    # General informational queries that don't match any negative markers
    if len(cleaned.split()) >= 3 and not any(w in cleaned for w in ("run", "execute", "call", "send")):
        return True, "informational_query", "Informational query eligible for standard cache TTL."

    return False, "unclassified", "Prompt does not match static informational eligibility rules; failing open to fresh generation."
