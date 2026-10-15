"""Deterministic Enterprise AI Cost Scaling Simulator for AIRLOCK."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from app.optimization.cost_calculator import MODEL_PRICING_TABLE


@dataclass
class ForecastScenario:
    name: str
    monthly_baseline_cost: float
    monthly_optimized_cost: float
    monthly_cache_infra_cost: float
    monthly_net_savings: float
    monthly_gross_savings: float
    savings_percentage: float
    annual_baseline_cost: float
    annual_net_savings: float
    avoided_requests_monthly: int
    avoided_tokens_monthly: int


@dataclass
class SimulationResult:
    active_users: int
    requests_per_user_day: float
    total_monthly_requests: int
    expected: ForecastScenario
    conservative: ForecastScenario
    optimistic: ForecastScenario
    assumptions: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "active_users": self.active_users,
            "requests_per_user_day": self.requests_per_user_day,
            "total_monthly_requests": self.total_monthly_requests,
            "expected": asdict(self.expected),
            "conservative": asdict(self.conservative),
            "optimistic": asdict(self.optimistic),
            "assumptions": self.assumptions,
        }


def _calculate_scenario(
    name: str,
    total_monthly_requests: int,
    avg_input_tokens: int,
    avg_output_tokens: int,
    cacheable_ratio: float,
    cache_hit_rate: float,
    pro_ratio: float,
    cache_infra_cost: float,
) -> ForecastScenario:
    flash_ratio = 1.0 - pro_ratio
    flash_pricing = MODEL_PRICING_TABLE["gemini-2.5-flash"]
    pro_pricing = MODEL_PRICING_TABLE["gemini-1.5-pro"]

    blended_input_cost_per_m = (
        flash_ratio * flash_pricing.input_cost_per_million + pro_ratio * pro_pricing.input_cost_per_million
    )
    blended_output_cost_per_m = (
        flash_ratio * flash_pricing.output_cost_per_million + pro_ratio * pro_pricing.output_cost_per_million
    )

    # 1. Baseline: 100% of requests go directly to Gemini models
    total_input_tokens = total_monthly_requests * avg_input_tokens
    total_output_tokens = total_monthly_requests * avg_output_tokens

    baseline_monthly_cost = (
        (total_input_tokens / 1_000_000.0) * blended_input_cost_per_m
        + (total_output_tokens / 1_000_000.0) * blended_output_cost_per_m
    )

    # 2. Optimized: Eligible requests hit the application response cache
    avoided_requests = int(total_monthly_requests * cacheable_ratio * cache_hit_rate)
    optimized_requests = total_monthly_requests - avoided_requests

    avoided_input_tokens = avoided_requests * avg_input_tokens
    avoided_output_tokens = avoided_requests * avg_output_tokens
    total_avoided_tokens = avoided_input_tokens + avoided_output_tokens

    optimized_monthly_api_cost = (
        ((total_input_tokens - avoided_input_tokens) / 1_000_000.0) * blended_input_cost_per_m
        + ((total_output_tokens - avoided_output_tokens) / 1_000_000.0) * blended_output_cost_per_m
    )

    monthly_gross_savings = baseline_monthly_cost - optimized_monthly_api_cost
    monthly_net_savings = monthly_gross_savings - cache_infra_cost
    savings_pct = (monthly_net_savings / baseline_monthly_cost * 100.0) if baseline_monthly_cost > 0 else 0.0

    return ForecastScenario(
        name=name,
        monthly_baseline_cost=round(baseline_monthly_cost, 2),
        monthly_optimized_cost=round(optimized_monthly_api_cost + cache_infra_cost, 2),
        monthly_cache_infra_cost=round(cache_infra_cost, 2),
        monthly_net_savings=round(monthly_net_savings, 2),
        monthly_gross_savings=round(monthly_gross_savings, 2),
        savings_percentage=round(savings_pct, 1),
        annual_baseline_cost=round(baseline_monthly_cost * 12, 2),
        annual_net_savings=round(monthly_net_savings * 12, 2),
        avoided_requests_monthly=avoided_requests,
        avoided_tokens_monthly=total_avoided_tokens,
    )


def simulate_enterprise_cost(
    active_users: int = 1000,
    requests_per_user_day: float = 12.0,
    avg_input_tokens: int = 650,
    avg_output_tokens: int = 350,
    cacheable_ratio: float = 0.40,
    expected_hit_rate: float = 0.65,
    pro_model_ratio: float = 0.15,
    cache_infra_cost_monthly: float = 25.0,
    active_days_per_month: int = 30,
) -> SimulationResult:
    """Run deterministic sensitivity simulation comparing unoptimized vs AIRLOCK-optimized operations."""
    total_monthly_requests = int(active_users * requests_per_user_day * active_days_per_month)

    # Expected scenario
    expected = _calculate_scenario(
        name="Expected",
        total_monthly_requests=total_monthly_requests,
        avg_input_tokens=avg_input_tokens,
        avg_output_tokens=avg_output_tokens,
        cacheable_ratio=cacheable_ratio,
        cache_hit_rate=expected_hit_rate,
        pro_ratio=pro_model_ratio,
        cache_infra_cost=cache_infra_cost_monthly,
    )

    # Conservative scenario (lower repetition, lower hit rate, higher infra buffer)
    conservative = _calculate_scenario(
        name="Conservative",
        total_monthly_requests=total_monthly_requests,
        avg_input_tokens=avg_input_tokens,
        avg_output_tokens=avg_output_tokens,
        cacheable_ratio=max(0.15, cacheable_ratio * 0.75),
        cache_hit_rate=max(0.30, expected_hit_rate * 0.75),
        pro_ratio=min(0.40, pro_model_ratio * 1.5),
        cache_infra_cost=cache_infra_cost_monthly * 1.5,
    )

    # Optimistic scenario (higher cache reuse across shared topics)
    optimistic = _calculate_scenario(
        name="Optimistic",
        total_monthly_requests=total_monthly_requests,
        avg_input_tokens=avg_input_tokens,
        avg_output_tokens=avg_output_tokens,
        cacheable_ratio=min(0.65, cacheable_ratio * 1.25),
        cache_hit_rate=min(0.85, expected_hit_rate * 1.2),
        pro_ratio=max(0.05, pro_model_ratio * 0.7),
        cache_infra_cost=cache_infra_cost_monthly,
    )

    assumptions = {
        "active_users": active_users,
        "requests_per_user_day": requests_per_user_day,
        "active_days_per_month": active_days_per_month,
        "avg_input_tokens": avg_input_tokens,
        "avg_output_tokens": avg_output_tokens,
        "cacheable_ratio_pct": round(cacheable_ratio * 100, 1),
        "expected_hit_rate_pct": round(expected_hit_rate * 100, 1),
        "pro_model_ratio_pct": round(pro_model_ratio * 100, 1),
        "flash_model_ratio_pct": round((1.0 - pro_model_ratio) * 100, 1),
        "cache_infra_cost_monthly_usd": cache_infra_cost_monthly,
    }

    return SimulationResult(
        active_users=active_users,
        requests_per_user_day=requests_per_user_day,
        total_monthly_requests=total_monthly_requests,
        expected=expected,
        conservative=conservative,
        optimistic=optimistic,
        assumptions=assumptions,
    )
