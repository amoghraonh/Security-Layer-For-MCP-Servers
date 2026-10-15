"""Cryptographic cache key generator ensuring tenant isolation and context integrity."""

from __future__ import annotations

import hashlib
import json
from typing import Any

CACHE_SCHEMA_VERSION = "v1.2"
DEFAULT_SYSTEM_INSTRUCTION_VERSION = "airlock-gateway-v2"


def generate_cache_key(
    prompt: str,
    tenant_id: str = "default",
    user_scope: str | None = None,
    model_id: str = "gemini-2.5-flash",
    system_instruction_version: str = DEFAULT_SYSTEM_INSTRUCTION_VERSION,
    is_shared_public: bool = False,
    extra_context: dict[str, Any] | None = None,
) -> str:
    """Generate a deterministic, secure SHA-256 cache key.

    Raw prompts are NEVER exposed in the key itself.
    Tenant isolation is enforced unless explicitly marked as shared public content.
    """
    normalized_prompt = " ".join(prompt.strip().lower().split())

    canonical_payload: dict[str, Any] = {
        "schema": CACHE_SCHEMA_VERSION,
        "prompt": normalized_prompt,
        "model": model_id.strip().lower(),
        "sys_ver": system_instruction_version,
    }

    if is_shared_public:
        canonical_payload["scope"] = "global_public"
    else:
        canonical_payload["tenant"] = tenant_id.strip().lower()
        if user_scope:
            canonical_payload["user"] = user_scope.strip().lower()

    if extra_context:
        sorted_context = {k: str(v) for k, v in sorted(extra_context.items())}
        canonical_payload["ctx"] = sorted_context

    serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
    key_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    prefix = "airlock:pub" if is_shared_public else f"airlock:ten:{tenant_id[:12]}"
    return f"{prefix}:{key_hash[:32]}"
