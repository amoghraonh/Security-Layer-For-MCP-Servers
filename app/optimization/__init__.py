"""AIRLOCK Optimization & Efficiency Module."""

from app.optimization.cache_eligibility import classify_cache_eligibility
from app.optimization.cache_interface import BaseResponseCache, CacheEntry, InMemoryResponseCache
from app.optimization.cache_keys import generate_cache_key
from app.optimization.cost_calculator import (
    MODEL_PRICING_TABLE,
    calculate_avoided_cost,
    calculate_cost,
    get_all_pricing,
    get_model_pricing,
)
from app.optimization.cost_forecaster import simulate_enterprise_cost
from app.optimization.model_router import route_model
from app.optimization.token_optimizer import TokenOptimizer, token_optimizer
from app.optimization.usage_collector import RequestEfficiencyRecord, UsageCollector, telemetry_collector

__all__ = [
    "BaseResponseCache",
    "CacheEntry",
    "InMemoryResponseCache",
    "MODEL_PRICING_TABLE",
    "RequestEfficiencyRecord",
    "TokenOptimizer",
    "UsageCollector",
    "calculate_avoided_cost",
    "calculate_cost",
    "classify_cache_eligibility",
    "generate_cache_key",
    "get_all_pricing",
    "get_model_pricing",
    "route_model",
    "simulate_enterprise_cost",
    "telemetry_collector",
    "token_optimizer",
]
