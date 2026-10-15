"""Comprehensive tests for AIRLOCK Intelligent Cache, Model Routing, and Cost Optimization."""

from pathlib import Path
import time
from fastapi.testclient import TestClient

from app.api.management import create_management_app
from app.agent.controller import ChatResult
from app.optimization.cache_eligibility import classify_cache_eligibility
from app.optimization.cache_interface import InMemoryResponseCache
from app.optimization.cache_keys import generate_cache_key
from app.optimization.cost_calculator import calculate_avoided_cost, calculate_cost, get_all_pricing
from app.optimization.cost_forecaster import simulate_enterprise_cost
from app.optimization.model_router import route_model
from app.optimization.token_optimizer import TokenOptimizer


class MockChatController:
    """Mock controller that tracks call count to prove model calls are avoided."""

    def __init__(self) -> None:
        self.call_count = 0

    async def handle_message(self, message: str) -> ChatResult:
        self.call_count += 1
        return ChatResult(answer=f"Synthesized response for: {message}", tool_results=[])


def test_cache_eligibility_classification() -> None:
    # Eligible educational and technical concepts
    eligible, cat, _ = classify_cache_eligibility("Explain the difference between authentication and authorization.")
    assert eligible is True
    assert cat in ("technical_explanation", "informational_query")

    eligible, cat, _ = classify_cache_eligibility("What is Zero Trust architecture according to NIST SP 800-207?")
    assert eligible is True

    # Ineligible tool operations
    eligible, cat, _ = classify_cache_eligibility("Delete resource group dev-rg-01")
    assert eligible is False
    assert cat == "tool_operation"

    eligible, cat, _ = classify_cache_eligibility("Restart VM dev-vm-01 immediately")
    assert eligible is False
    assert cat == "tool_operation"

    # Ineligible sensitive / dynamic content
    eligible, cat, _ = classify_cache_eligibility("What is the current time right now?")
    assert eligible is False
    assert cat == "dynamic_or_sensitive"

    eligible, cat, _ = classify_cache_eligibility("Read ../../etc/passwd")
    assert eligible is False
    assert cat == "dynamic_or_sensitive"

    # Context override
    eligible, cat, _ = classify_cache_eligibility("General overview", context={"tool_execution": True})
    assert eligible is False
    assert cat == "stateful_tool"


def test_in_memory_response_cache_lru_and_expiry() -> None:
    cache = InMemoryResponseCache(max_entries=3, default_ttl=2)

    cache.set("k1", "c1", "gemini-2.5-flash", 100, 50, ttl_seconds=10, tenant_id="t1")
    cache.set("k2", "c2", "gemini-2.5-flash", 100, 50, ttl_seconds=10, tenant_id="t1")
    cache.set("k3", "c3", "gemini-2.5-flash", 100, 50, ttl_seconds=10, tenant_id="t2")

    assert cache.get("k1") is not None
    assert cache.get("k2") is not None
    assert cache.get("k3") is not None

    # Adding a 4th entry should evict k1 (since k2 and k3 were accessed, but k1 was least recently accessed before k2 & k3)
    # Let's access k2 and k3 to make k1 the oldest
    _ = cache.get("k2")
    _ = cache.get("k3")
    cache.set("k4", "c4", "gemini-2.5-flash", 100, 50, ttl_seconds=10, tenant_id="t1")

    assert cache.get("k1") is None  # Evicted
    assert cache.get("k4") is not None

    # Test tenant-isolated invalidation
    cleared_t1 = cache.invalidate_all(tenant_id="t1")
    assert cleared_t1 >= 1
    assert cache.get("k4") is None
    assert cache.get("k3") is not None  # Tenant t2 preserved


def test_cache_key_tenant_isolation() -> None:
    key_tenant_a = generate_cache_key("Check access policy", tenant_id="tenant-alpha", is_shared_public=False)
    key_tenant_b = generate_cache_key("Check access policy", tenant_id="tenant-beta", is_shared_public=False)

    assert key_tenant_a != key_tenant_b
    assert "tenant-alpha" in key_tenant_a or "alpha" in key_tenant_a


def test_token_optimizer_avoids_repeated_inference() -> None:
    optimizer = TokenOptimizer(cache=InMemoryResponseCache(max_entries=100, default_ttl=3600))
    mock_calls = 0

    def mock_llm(model: str, p: str) -> tuple[str, int, int, int]:
        nonlocal mock_calls
        mock_calls += 1
        return f"Generated answer for {p}", 250, 150, 0

    prompt = "Explain the difference between RBAC and ABAC."

    # First request: Cache MISS -> invokes LLM
    res1 = optimizer.process_prompt(prompt, tenant_id="acme-corp", llm_caller=mock_llm)
    assert res1["cache_status"] == "MISS"
    assert mock_calls == 1
    assert "RBAC" in res1["content"]

    # Second request: Cache HIT -> returns cached answer WITHOUT invoking LLM!
    res2 = optimizer.process_prompt(prompt, tenant_id="acme-corp", llm_caller=mock_llm)
    assert res2["cache_status"] == "HIT"
    assert mock_calls == 1  # LLM call was SKIPPED!
    assert res2["actual_cost"] == 0.0
    assert res2["avoided_input_tokens"] == 250
    assert res2["avoided_output_tokens"] == 150
    assert res2["avoided_cost"] > 0


def test_cost_calculator_and_pricing_schedule() -> None:
    pricing = get_all_pricing()
    assert pricing["version"] == "2026-Q1-v2"
    assert "gemini-2.5-flash" in pricing["models"]
    assert "gemini-1.5-pro" in pricing["models"]

    # Flash calculation: 100k input ($0.075/1M), 20k output ($0.30/1M)
    cost = calculate_cost("gemini-2.5-flash", 100_000, 20_000, cached_input_tokens=0)
    expected_cost = (100_000 / 1_000_000 * 0.075) + (20_000 / 1_000_000 * 0.30)
    assert abs(cost - expected_cost) < 1e-6

    # Avoided cost
    avoided = calculate_avoided_cost("gemini-2.5-flash", 500, 300)
    assert avoided > 0.0


def test_cost_scaling_simulator() -> None:
    sim = simulate_enterprise_cost(
        active_users=1000,
        requests_per_user_day=10.0,
        avg_input_tokens=600,
        avg_output_tokens=300,
        cacheable_ratio=0.40,
        expected_hit_rate=0.60,
        cache_infra_cost_monthly=20.0,
    )
    result = sim.to_dict()
    assert result["active_users"] == 1000
    assert result["total_monthly_requests"] == 300_000

    exp = result["expected"]
    assert exp["monthly_baseline_cost"] > exp["monthly_optimized_cost"]
    assert exp["monthly_net_savings"] > 0
    assert exp["savings_percentage"] > 0
    assert exp["avoided_requests_monthly"] == int(300_000 * 0.40 * 0.60)


def test_efficiency_api_routes(tmp_path: Path) -> None:
    mock_ctrl = MockChatController()
    app = create_management_app(tmp_path / "audit.db", chat_controller=mock_ctrl, auth_path=tmp_path / "auth.db")

    with TestClient(app) as client:
        # 1. Pricing endpoint
        p_res = client.get("/api/efficiency/pricing")
        assert p_res.status_code == 200
        assert "models" in p_res.json()

        # 2. Metrics endpoint
        m_res = client.get("/api/efficiency/metrics")
        assert m_res.status_code == 200
        data = m_res.json()
        assert "telemetry" in data
        assert "cache_health" in data

        # 3. Records endpoint
        r_res = client.get("/api/efficiency/records?limit=10")
        assert r_res.status_code == 200
        assert "records" in r_res.json()

        # 4. Simulation endpoint
        sim_payload = {
            "active_users": 500,
            "requests_per_user_day": 8.0,
            "avg_input_tokens": 500,
            "avg_output_tokens": 200,
            "cacheable_ratio": 0.35,
            "expected_hit_rate": 0.50,
            "pro_model_ratio": 0.10,
            "cache_infra_cost_monthly": 15.0,
            "active_days_per_month": 30,
        }
        s_res = client.post("/api/efficiency/simulate", json=sim_payload)
        assert s_res.status_code == 200
        assert "simulation" in s_res.json()
        sim_data = s_res.json()["simulation"]
        assert sim_data["active_users"] == 500
