"""Central AIRLOCK Token Optimizer and Cache Coordinator."""

from __future__ import annotations

import time
from typing import Any, Callable

from app.optimization.cache_eligibility import classify_cache_eligibility
from app.optimization.cache_interface import BaseResponseCache, InMemoryResponseCache
from app.optimization.cache_keys import generate_cache_key
from app.optimization.model_router import route_model
from app.optimization.usage_collector import telemetry_collector


class TokenOptimizer:
    """Coordinates prompt classification, response caching, model routing, and cost telemetry."""

    def __init__(self, cache: BaseResponseCache | None = None) -> None:
        self.cache = cache or InMemoryResponseCache(max_entries=2000, default_ttl=3600)
        self.telemetry = telemetry_collector

    def process_prompt(
        self,
        prompt: str,
        tenant_id: str = "airlock-enterprise",
        user_id: str = "anonymous",
        context: dict[str, Any] | None = None,
        llm_caller: Callable[[str, str], tuple[str, int, int, int]] | None = None,
    ) -> dict[str, Any]:
        """Process prompt through AIRLOCK optimization pipeline.

        Args:
            prompt: User input string.
            tenant_id: Organization or tenant identifier.
            user_id: Requesting user identity.
            context: Additional conversation or tool context.
            llm_caller: Optional callable (model_id, prompt) -> (content, in_tokens, out_tokens, cached_in_tokens).

        Returns:
            Dictionary containing response content, cache metrics, and optimization metadata.
        """
        start_time = time.time()

        # Step 1: Safe Cache Eligibility Classification
        is_eligible, category, reason = classify_cache_eligibility(prompt, context)

        # Step 2: Intelligent Model Routing
        selected_model, routing_reason = route_model(prompt, context)

        cache_key = ""
        if is_eligible:
            is_public_concept = category in ("technical_explanation", "informational_query")
            cache_key = generate_cache_key(
                prompt=prompt,
                tenant_id=tenant_id,
                user_scope=None if is_public_concept else user_id,
                model_id=selected_model,
                is_shared_public=is_public_concept,
            )

            # Step 3: Cache Lookup
            cached_entry = self.cache.get(cache_key)
            if cached_entry is not None:
                latency_ms = (time.time() - start_time) * 1000.0
                rec = self.telemetry.record_request(
                    tenant_id=tenant_id,
                    user_id=user_id,
                    model=cached_entry.model,
                    prompt=prompt,
                    cache_status="HIT",
                    latency_ms=latency_ms,
                    input_tokens=0,
                    output_tokens=0,
                    cached_input_tokens=0,
                    avoided_input_tokens=cached_entry.input_tokens,
                    avoided_output_tokens=cached_entry.output_tokens,
                    optimization_type="application_cache",
                )

                return {
                    "content": cached_entry.content,
                    "cache_status": "HIT",
                    "cache_key": cache_key,
                    "model": cached_entry.model,
                    "latency_ms": round(latency_ms, 1),
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "avoided_input_tokens": cached_entry.input_tokens,
                    "avoided_output_tokens": cached_entry.output_tokens,
                    "actual_cost": 0.0,
                    "avoided_cost": rec.avoided_cost,
                    "optimization_type": "application_cache",
                    "routing_reason": routing_reason,
                    "eligibility_reason": reason,
                    "request_id": rec.request_id,
                }

        # Step 4: Fresh LLM Generation (Cache Miss or Ineligible)
        cache_status = "MISS" if is_eligible else "INELIGIBLE"

        # Bounded conversation context simulation
        trimmed_prompt = prompt.strip()

        if llm_caller:
            content, in_tokens, out_tokens, cached_tokens = llm_caller(selected_model, trimmed_prompt)
        else:
            # Fallback estimation if caller not provided
            content = f"[AIRLOCK Generated Response] Direct inference completed for: {trimmed_prompt[:60]}..."
            in_tokens = max(10, len(trimmed_prompt.split()) * 2)
            out_tokens = max(20, len(content.split()) * 2)
            cached_tokens = 0

        latency_ms = (time.time() - start_time) * 1000.0

        # Step 5: Store in cache if eligible
        if is_eligible and cache_key:
            # TTL: 2 hours for technical concepts, 1 hour for general informational
            ttl = 7200 if category == "technical_explanation" else 3600
            self.cache.set(
                key=cache_key,
                content=content,
                model=selected_model,
                input_tokens=in_tokens,
                output_tokens=out_tokens,
                ttl_seconds=ttl,
                tenant_id=tenant_id,
                category=category,
            )

        rec = self.telemetry.record_request(
            tenant_id=tenant_id,
            user_id=user_id,
            model=selected_model,
            prompt=prompt,
            cache_status=cache_status,
            latency_ms=latency_ms,
            input_tokens=in_tokens,
            output_tokens=out_tokens,
            cached_input_tokens=cached_tokens,
            avoided_input_tokens=0,
            avoided_output_tokens=0,
            optimization_type="model_routing" if is_eligible else "security_enforcement",
        )

        return {
            "content": content,
            "cache_status": cache_status,
            "cache_key": cache_key,
            "model": selected_model,
            "latency_ms": round(latency_ms, 1),
            "input_tokens": in_tokens,
            "output_tokens": out_tokens,
            "avoided_input_tokens": 0,
            "avoided_output_tokens": 0,
            "actual_cost": rec.actual_cost,
            "avoided_cost": 0.0,
            "optimization_type": "model_routing" if is_eligible else "security_enforcement",
            "routing_reason": routing_reason,
            "eligibility_reason": reason,
            "request_id": rec.request_id,
        }

    def invalidate_cache(self, tenant_id: str | None = None) -> int:
        """Invalidate cached entries."""
        return self.cache.invalidate_all(tenant_id)

    def cache_stats(self) -> dict[str, Any]:
        """Return cache health metrics."""
        return self.cache.stats()


# Singleton token optimizer
token_optimizer = TokenOptimizer()
