"""Enterprise AI cost accounting and token pricing schedules for AIRLOCK."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

PRICING_SCHEDULE_VERSION = "2026-Q1-v2"


@dataclass(frozen=True)
class ModelPricing:
    model_id: str
    display_name: str
    input_cost_per_million: float
    cached_input_cost_per_million: float
    output_cost_per_million: float
    effective_date: str = "2026-01-01"


# Official Google Gemini reference rates per 1M tokens
MODEL_PRICING_TABLE: dict[str, ModelPricing] = {
    "gemini-2.5-flash": ModelPricing(
        model_id="gemini-2.5-flash",
        display_name="Gemini 2.5 Flash (Ultra-Low Latency)",
        input_cost_per_million=0.075,
        cached_input_cost_per_million=0.01875,
        output_cost_per_million=0.30,
    ),
    "gemini-1.5-flash": ModelPricing(
        model_id="gemini-1.5-flash",
        display_name="Gemini 1.5 Flash",
        input_cost_per_million=0.075,
        cached_input_cost_per_million=0.01875,
        output_cost_per_million=0.30,
    ),
    "gemini-1.5-pro": ModelPricing(
        model_id="gemini-1.5-pro",
        display_name="Gemini 1.5 Pro (Deep Reasoning)",
        input_cost_per_million=1.25,
        cached_input_cost_per_million=0.3125,
        output_cost_per_million=5.00,
    ),
}

DEFAULT_MODEL = "gemini-2.5-flash"


def get_model_pricing(model_id: str | None) -> ModelPricing:
    """Retrieve pricing definition for a model, defaulting to standard Flash pricing."""
    if not model_id:
        return MODEL_PRICING_TABLE[DEFAULT_MODEL]
    key = model_id.strip().lower()
    return MODEL_PRICING_TABLE.get(key, MODEL_PRICING_TABLE[DEFAULT_MODEL])


def calculate_cost(
    model_id: str,
    input_tokens: int,
    output_tokens: int,
    cached_input_tokens: int = 0,
) -> float:
    """Calculate the precise dollar cost for an inference request.

    Note: Cached input tokens are charged at the discounted context-cache rate,
    while fresh uncached input tokens are charged at the full rate.
    """
    pricing = get_model_pricing(model_id)
    uncached_inputs = max(0, input_tokens - cached_input_tokens)

    cost_uncached_in = (uncached_inputs / 1_000_000.0) * pricing.input_cost_per_million
    cost_cached_in = (cached_input_tokens / 1_000_000.0) * pricing.cached_input_cost_per_million
    cost_out = (output_tokens / 1_000_000.0) * pricing.output_cost_per_million

    return round(cost_uncached_in + cost_cached_in + cost_out, 7)


def calculate_avoided_cost(
    model_id: str,
    avoided_input_tokens: int,
    avoided_output_tokens: int,
) -> float:
    """Calculate the dollar cost avoided by serving a response from cache."""
    pricing = get_model_pricing(model_id)
    cost_in = (avoided_input_tokens / 1_000_000.0) * pricing.input_cost_per_million
    cost_out = (avoided_output_tokens / 1_000_000.0) * pricing.output_cost_per_million
    return round(cost_in + cost_out, 7)


def get_all_pricing() -> dict[str, Any]:
    """Return serialized pricing schedules for UI display."""
    return {
        "version": PRICING_SCHEDULE_VERSION,
        "currency": "USD",
        "models": {
            k: {
                "model_id": v.model_id,
                "display_name": v.display_name,
                "input_per_million": v.input_cost_per_million,
                "cached_input_per_million": v.cached_input_cost_per_million,
                "output_per_million": v.output_cost_per_million,
                "effective_date": v.effective_date,
            }
            for k, v in MODEL_PRICING_TABLE.items()
        },
    }
