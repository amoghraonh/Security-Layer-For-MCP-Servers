"""Thread-safe usage telemetry collector and aggregation engine for AIRLOCK."""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import asdict, dataclass
from typing import Any

from app.optimization.cost_calculator import calculate_avoided_cost, calculate_cost


@dataclass
class RequestEfficiencyRecord:
    request_id: str
    timestamp: float
    tenant_id: str
    user_id: str
    model: str
    prompt_summary: str
    cache_status: str  # "HIT", "MISS", "INELIGIBLE"
    latency_ms: float
    input_tokens: int
    output_tokens: int
    cached_input_tokens: int
    avoided_input_tokens: int
    avoided_output_tokens: int
    actual_cost: float
    avoided_cost: float
    optimization_type: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["formatted_timestamp"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)
        )
        return data


class UsageCollector:
    """Collects and aggregates request-level AI token and cost telemetry."""

    def __init__(self, max_records: int = 500) -> None:
        self.max_records = max_records
        self._records: list[RequestEfficiencyRecord] = []
        self._lock = threading.RLock()
        self._seed_baseline_telemetry()

    def _seed_baseline_telemetry(self) -> None:
        """Seed realistic baseline enterprise telemetry for demonstration."""
        now = time.time()
        sample_prompts = [
            ("Explain the difference between authentication and authorization.", "HIT", 18, 0, 0, 420, 280, "gemini-2.5-flash", "application_cache"),
            ("Define Zero Trust architecture according to NIST SP 800-207.", "HIT", 22, 0, 0, 510, 390, "gemini-2.5-flash", "application_cache"),
            ("What is the OWASP Top 10 for LLMs?", "HIT", 15, 0, 0, 480, 350, "gemini-2.5-flash", "application_cache"),
            ("Assess risk for Azure resource group deprovisioning.", "INELIGIBLE", 145, 620, 180, 0, 0, "gemini-1.5-pro", "security_enforcement"),
            ("Generate a security policy for MCP tool rate-limiting.", "MISS", 210, 750, 410, 0, 0, "gemini-1.5-pro", "model_routing"),
            ("What are the key principles of defense-in-depth?", "HIT", 19, 0, 0, 390, 310, "gemini-2.5-flash", "application_cache"),
            ("Check synthetic database secret permissions.", "INELIGIBLE", 165, 590, 140, 0, 0, "gemini-1.5-pro", "security_enforcement"),
            ("Summarize the blast radius of unverified bash execution in container.", "MISS", 230, 810, 490, 0, 0, "gemini-1.5-pro", "model_routing"),
            ("Explain how AIRLOCK intercepts MCP stdio protocol payloads.", "HIT", 25, 0, 0, 540, 420, "gemini-2.5-flash", "application_cache"),
            ("Explain token bucket rate limiting for AI agents.", "HIT", 17, 0, 0, 430, 320, "gemini-2.5-flash", "application_cache"),
        ]

        # Generate 45 baseline requests spread over the past 2 hours
        for i in range(45):
            prompt, status, lat, in_tok, out_tok, av_in, av_out, model, opt_type = sample_prompts[i % len(sample_prompts)]
            t = now - (45 - i) * 160
            actual_cost = calculate_cost(model, in_tok, out_tok, 0)
            avoided_cost = calculate_avoided_cost(model, av_in, av_out)

            record = RequestEfficiencyRecord(
                request_id=f"req-seed-{1000 + i}",
                timestamp=t,
                tenant_id="airlock-enterprise",
                user_id="sec-operator" if i % 2 == 0 else "dev-engineer",
                model=model,
                prompt_summary=prompt,
                cache_status=status,
                latency_ms=lat + (i % 7) * 4,
                input_tokens=in_tok,
                output_tokens=out_tok,
                cached_input_tokens=0,
                avoided_input_tokens=av_in,
                avoided_output_tokens=av_out,
                actual_cost=actual_cost,
                avoided_cost=avoided_cost,
                optimization_type=opt_type,
            )
            self._records.append(record)

    def record_request(
        self,
        tenant_id: str,
        user_id: str,
        model: str,
        prompt: str,
        cache_status: str,
        latency_ms: float,
        input_tokens: int,
        output_tokens: int,
        cached_input_tokens: int = 0,
        avoided_input_tokens: int = 0,
        avoided_output_tokens: int = 0,
        optimization_type: str = "fresh_generation",
        request_id: str | None = None,
    ) -> RequestEfficiencyRecord:
        """Record a single AI request with calculated costs."""
        now = time.time()
        actual_cost = calculate_cost(model, input_tokens, output_tokens, cached_input_tokens)
        avoided_cost = calculate_avoided_cost(model, avoided_input_tokens, avoided_output_tokens)

        # Truncate prompt for summary display
        summary = prompt.strip()
        if len(summary) > 80:
            summary = summary[:77] + "..."

        record = RequestEfficiencyRecord(
            request_id=request_id or f"req-{uuid.uuid4().hex[:8]}",
            timestamp=now,
            tenant_id=tenant_id,
            user_id=user_id,
            model=model,
            prompt_summary=summary,
            cache_status=cache_status,
            latency_ms=round(latency_ms, 1),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cached_input_tokens=cached_input_tokens,
            avoided_input_tokens=avoided_input_tokens,
            avoided_output_tokens=avoided_output_tokens,
            actual_cost=actual_cost,
            avoided_cost=avoided_cost,
            optimization_type=optimization_type,
        )

        with self._lock:
            self._records.append(record)
            if len(self._records) > self.max_records:
                self._records.pop(0)

        return record

    def get_records(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return [r.to_dict() for r in reversed(self._records[-limit:])]

    def get_summary_metrics(self) -> dict[str, Any]:
        with self._lock:
            total_requests = len(self._records)
            if total_requests == 0:
                return {
                    "total_requests": 0,
                    "cache_hits": 0,
                    "cache_misses": 0,
                    "ineligible_requests": 0,
                    "cache_hit_rate_pct": 0.0,
                    "actual_input_tokens": 0,
                    "actual_output_tokens": 0,
                    "cached_input_tokens": 0,
                    "avoided_tokens": 0,
                    "actual_api_spend_usd": 0.0,
                    "avoided_cost_usd": 0.0,
                    "avg_latency_ms": 0.0,
                    "cost_per_request_usd": 0.0,
                }

            cache_hits = sum(1 for r in self._records if r.cache_status == "HIT")
            cache_misses = sum(1 for r in self._records if r.cache_status == "MISS")
            ineligible = sum(1 for r in self._records if r.cache_status == "INELIGIBLE")

            # Hit rate over eligible requests
            eligible_count = cache_hits + cache_misses
            hit_rate = (cache_hits / eligible_count * 100) if eligible_count > 0 else 0.0

            actual_in = sum(r.input_tokens for r in self._records)
            actual_out = sum(r.output_tokens for r in self._records)
            cached_in = sum(r.cached_input_tokens for r in self._records)
            avoided_tokens = sum(r.avoided_input_tokens + r.avoided_output_tokens for r in self._records)

            actual_spend = sum(r.actual_cost for r in self._records)
            avoided_spend = sum(r.avoided_cost for r in self._records)
            avg_latency = sum(r.latency_ms for r in self._records) / total_requests
            cost_per_req = actual_spend / total_requests if total_requests > 0 else 0.0

            # Model distribution
            model_counts: dict[str, int] = {}
            for r in self._records:
                model_counts[r.model] = model_counts.get(r.model, 0) + 1

            return {
                "total_requests": total_requests,
                "cache_hits": cache_hits,
                "cache_misses": cache_misses,
                "ineligible_requests": ineligible,
                "cache_hit_rate_pct": round(hit_rate, 1),
                "actual_input_tokens": actual_in,
                "actual_output_tokens": actual_out,
                "cached_input_tokens": cached_in,
                "avoided_tokens": avoided_tokens,
                "actual_api_spend_usd": round(actual_spend, 5),
                "avoided_cost_usd": round(avoided_spend, 5),
                "avg_latency_ms": round(avg_latency, 1),
                "cost_per_request_usd": round(cost_per_req, 6),
                "model_distribution": model_counts,
            }


# Singleton usage collector
telemetry_collector = UsageCollector()
