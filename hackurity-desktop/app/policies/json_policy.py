"""Deterministic, deny-by-default authorization from local JSON configuration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: str


class JsonPolicy:
    """Evaluate only trusted local configuration, never agent-supplied permissions."""

    def __init__(self, document: dict[str, Any]) -> None:
        self._document = document

    @classmethod
    def from_file(cls, path: Path) -> "JsonPolicy":
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def approved_tool_names(self, trusted_identity: str) -> set[str]:
        identity = self._identities().get(trusted_identity, {})
        return set(identity.get("allowed_tools", []))

    def authorize(self, trusted_identity: str, tool_name: str, arguments: dict[str, Any]) -> AuthorizationDecision:
        """Return a decision without consulting caller claims or untrusted text."""
        identity = self._identities().get(trusted_identity)
        if identity is None:
            return AuthorizationDecision(False, "No trusted server-side identity is configured")
        if tool_name not in identity.get("allowed_tools", []):
            return AuthorizationDecision(False, f"Policy denies tool: {tool_name}")
        if tool_name in {"list_resources", "list_local_repository_files", "list_synthetic_azure_resources"}:
            if arguments:
                return AuthorizationDecision(False, f"{tool_name} does not accept arguments")
            return AuthorizationDecision(True, "Allowed by local policy")
        if tool_name == "restart_vm":
            resource_name = arguments.get("resource_name")
            if set(arguments) != {"resource_name"} or not isinstance(resource_name, str):
                return AuthorizationDecision(False, "restart_vm requires one string resource_name")
            if resource_name not in identity.get("restart_vm_resources", []):
                return AuthorizationDecision(False, f"Policy denies VM: {resource_name}")
            return AuthorizationDecision(True, "Allowed by local policy")
        if tool_name == "read_local_repository_file":
            relative_path = arguments.get("relative_path")
            if set(arguments) != {"relative_path"} or not isinstance(relative_path, str):
                return AuthorizationDecision(False, "read_local_repository_file requires one string relative_path")
            if relative_path.startswith(("/", "\\")) or ".." in relative_path.replace("\\", "/").split("/"):
                return AuthorizationDecision(False, "Policy denies repository path traversal")
            prefixes = identity.get("local_repository_path_prefixes", [])
            if not any(relative_path.startswith(prefix) for prefix in prefixes):
                return AuthorizationDecision(False, f"Policy denies repository path: {relative_path}")
            return AuthorizationDecision(True, "Allowed read of local fixture path")
        if tool_name == "get_synthetic_azure_resource":
            resource_name = arguments.get("resource_name")
            if set(arguments) != {"resource_name"} or not isinstance(resource_name, str):
                return AuthorizationDecision(False, "get_synthetic_azure_resource requires one string resource_name")
            if resource_name not in identity.get("synthetic_azure_resources", []):
                return AuthorizationDecision(False, f"Policy denies synthetic Azure resource: {resource_name}")
            return AuthorizationDecision(True, "Allowed read of fictional local Azure metadata")
        return AuthorizationDecision(False, "No argument-validation rule exists for this tool")

    def _identities(self) -> dict[str, dict[str, Any]]:
        identities = self._document.get("trusted_identities", {})
        return identities if isinstance(identities, dict) else {}
