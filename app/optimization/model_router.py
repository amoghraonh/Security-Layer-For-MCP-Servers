"""Task-based dynamic model router for cost optimization."""

from __future__ import annotations

import re
from typing import Any

COMPLEX_TASK_PATTERNS = [
    re.compile(r"(?i)\b(architect|synthesize|security audit|threat model|code review|refactor|vulnerability analysis|blast radius)\b"),
    re.compile(r"(?i)\b(implement|generate policy|complex|deep dive|forensic)\b"),
]

FLASH_MODEL = "gemini-2.5-flash"
PRO_MODEL = "gemini-1.5-pro"


def route_model(prompt: str, context: dict[str, Any] | None = None) -> tuple[str, str]:
    """Select the most cost-effective supported Gemini model for the prompt.

    Returns:
        (model_id, routing_reason)
    """
    cleaned = prompt.strip().lower()

    # Complex reasoning or high-depth security synthesis
    for pattern in COMPLEX_TASK_PATTERNS:
        if pattern.search(cleaned):
            return PRO_MODEL, "Complex task pattern detected; routed to high-capacity reasoning model."

    # Long prompts requiring deep context reasoning
    if len(cleaned.split()) > 150:
        return PRO_MODEL, "Extensive context query; routed to high-capacity reasoning model."

    # Default to fast, low-cost Flash model
    return FLASH_MODEL, "Standard informational query; routed to ultra-low-latency, cost-efficient model."
