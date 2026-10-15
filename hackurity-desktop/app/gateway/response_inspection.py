"""Bounded, rule-based inspection of untrusted upstream tool response text."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path


VALID_ACTIONS = {"allow", "flag", "quarantine"}
IGNORE_INSTRUCTIONS = re.compile(
    r"(?:^|[.!?]\s+)(?:please\s+)?ignore\s+(?:all\s+)?previous\s+instructions",
    re.IGNORECASE,
)
SYSTEM_OVERRIDE = re.compile(
    r"(?:^|[.!?]\s+)(?:please\s+)?(?:override|replace|ignore)\s+(?:the\s+)?(?:system|developer)\s+instructions",
    re.IGNORECASE,
)
REVEAL_SECRETS = re.compile(
    r"(?:^|[.!?]\s+)(?:please\s+)?(?:reveal|send|exfiltrate)\s+(?:all\s+)?(?:secrets|credentials|api keys|tokens)",
    re.IGNORECASE,
)
DESTRUCTIVE_TOOL = re.compile(
    r"(?:^|[.!?]\s+)(?:please\s+)?(?:invoke|call|run|execute)\s+.*(?:delete_resource|rm\s+-rf|drop\s+database)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class InspectionResult:
    matches: tuple[str, ...]
    byte_length: int

    @property
    def suspicious(self) -> bool:
        return bool(self.matches)


class ResponseInspector:
    """Inspect text only; never execute, deserialize, or follow response instructions."""

    def __init__(self, action: str, max_response_bytes: int) -> None:
        if action not in VALID_ACTIONS:
            raise ValueError(f"Unsupported response inspection action: {action}")
        if max_response_bytes <= 0:
            raise ValueError("max_response_bytes must be positive")
        self.action = action
        self.max_response_bytes = max_response_bytes

    @classmethod
    def from_file(cls, path: Path) -> "ResponseInspector":
        document = json.loads(path.read_text(encoding="utf-8"))
        return cls(
            action=document.get("action", "quarantine"),
            max_response_bytes=document.get("max_response_bytes", 16384),
        )

    def inspect(self, response_text: str) -> InspectionResult:
        """Return rule labels only; caller chooses the configured response action."""
        encoded = response_text.encode("utf-8", errors="replace")
        if len(encoded) > self.max_response_bytes:
            return InspectionResult(("response_too_large",), len(encoded))

        matches: list[str] = []
        if IGNORE_INSTRUCTIONS.search(response_text):
            matches.append("ignore_previous_instructions")
        if REVEAL_SECRETS.search(response_text):
            matches.append("reveal_secrets")
        if SYSTEM_OVERRIDE.search(response_text):
            matches.append("override_system_or_developer")
        if DESTRUCTIVE_TOOL.search(response_text):
            matches.append("unrelated_destructive_tool")
        return InspectionResult(tuple(matches), len(encoded))
