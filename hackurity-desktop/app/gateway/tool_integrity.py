"""Fingerprint approved upstream MCP tool definitions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class DiscoveredTool:
    server_identity: str
    name: str
    description: str
    input_schema: dict[str, Any]

    def canonical_bytes(self) -> bytes:
        """Produce one repeatable byte representation before hashing."""
        document = {
            "description": self.description,
            "input_schema": self.input_schema,
            "server_identity": self.server_identity,
            "tool_name": self.name,
        }
        return json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("utf-8")

    def fingerprint(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class ApprovalRegistry:
    """Local approval records; absence or mismatch always means not approved."""

    def __init__(self, approvals: dict[str, dict[str, str]]) -> None:
        self._approvals = approvals

    @classmethod
    def from_file(cls, path: Path) -> "ApprovalRegistry":
        if not path.exists():
            return cls({})
        document = json.loads(path.read_text(encoding="utf-8"))
        approvals = document.get("approved_tools", {})
        return cls(approvals if isinstance(approvals, dict) else {})

    def is_approved(self, tool: DiscoveredTool) -> bool:
        approved = self._approvals.get(tool.name)
        return bool(
            approved
            and approved.get("server_identity") == tool.server_identity
            and approved.get("fingerprint") == tool.fingerprint()
        )


def write_approvals(path: Path, tools: list[DiscoveredTool]) -> None:
    """Replace approval records after an explicit administrator action."""
    document = {
        "version": 1,
        "approved_tools": {
            tool.name: {
                "server_identity": tool.server_identity,
                "fingerprint": tool.fingerprint(),
            }
            for tool in sorted(tools, key=lambda item: item.name)
        },
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
