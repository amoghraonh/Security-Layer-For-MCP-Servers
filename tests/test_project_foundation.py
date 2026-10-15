"""Fast checks that the initial project is importable and safely configured."""

import json
from pathlib import Path

import app


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_app_package_imports() -> None:
    """The empty application package must be importable before implementation."""
    assert app.__doc__


def test_example_policy_is_deny_by_default() -> None:
    """The first policy artifact must never grant access by default."""
    policy = json.loads((PROJECT_ROOT / "config" / "policy.example.json").read_text())
    assert policy["default_effect"] == "deny"
    assert policy["allow"] == []
