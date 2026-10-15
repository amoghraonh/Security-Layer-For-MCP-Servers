# AIRLOCK — Prompt Caching, Efficiency Engine & Judge Code Reference
**How Repeated Prompts are Secured, Cached, and Measured — Plus Hackathon Judge Cheat Sheet**
*Tagline: "AI Moves. AIRLOCK Decides."*

---

## Part 1: How AIRLOCK Saves Repeated Cache Prompts

### 1. The Core Security Rule: "Safety Precedes Performance"
Many AI caching proxies naively cache all prompts based on string similarity. In an autonomous agent environment connected to infrastructure via MCP, **caching tool execution results or dynamic commands is a critical vulnerability**. 

AIRLOCK enforces a **Strict Eligibility Barrier** before any prompt can touch the cache:

```
                          Incoming User / Agent Prompt
                                       |
                                       v
                     +-----------------------------------+
                     |    classify_cache_eligibility()   |
                     |  (app/optimization/cache_elig.py) |
                     +-----------------------------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
         [Matches Ineligible Markers]            [Passes Safety Guardrails]
         - Tool calls ("delete", "restart", etc.) - Concepts ("Explain Zero Trust")
         - Credentials ("api_key", "password")    - Architecture guides
         - Dynamic state ("now", "live", "today") - Standard educational queries
         - Path traversal ("../", "..\")                   |
                   |                                       v
                   v                              [ELIGIBLE FOR CACHE]
         [INELIGIBLE: BYPASS CACHE]                        |
         - Route directly to Model / MCP Gateway          v
         - Tag telemetry as "INELIGIBLE"         Generate Cryptographic Key
                                                 (app/optimization/cache_keys.py)
```

---

### 2. Cryptographic Key Derivation (`app/optimization/cache_keys.py`)
AIRLOCK derives a deterministic, collision-resistant **SHA-256 Cache Key** that guarantees strict tenant isolation:

1. **Normalization**:
   - The raw prompt is trimmed, lowercased, and internal whitespace is collapsed:
     ```python
     normalized_prompt = " ".join(prompt.strip().lower().split())
     ```
2. **Canonical JSON Serialization**:
   - A canonical dictionary is constructed and serialized with sorted keys to ensure bit-level reproducibility:
     ```python
     canonical_payload = {
         "schema": "v1.2",
         "prompt": normalized_prompt,
         "model": "gemini-2.5-flash",
         "sys_ver": "airlock-gateway-v2",
         "tenant": "default",  # Or "scope": "global_public"
         "ctx": sorted_context # Optional sorted context
     }
     serialized = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))
     ```
3. **SHA-256 Digest**:
   - The key is computed and prefixed:
     ```python
     key_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
     cache_key = f"airlock:ten:{tenant_id[:12]}:{key_hash[:32]}"
     ```
4. **Privacy Protection**:
   - Raw user prompts or sensitive text are **never exposed in the key name**.

---

### 3. Bounded In-Memory LRU Storage (`app/optimization/cache_interface.py`)
Cached prompts and responses are stored in a thread-safe, memory-bounded LRU (Least Recently Used) cache:

```python
@dataclass
class CacheEntry:
    key: str                    # SHA-256 derived cache key
    content: str                # Cached AI response
    model: str                  # AI model (e.g. "gemini-2.5-flash")
    input_tokens: int           # Avoided prompt tokens on hit
    output_tokens: int          # Avoided completion tokens on hit
    created_at: float           # Epoch creation time
    expires_at: float           # Epoch expiration time (default TTL: 3600s)
    tenant_id: str              # Isolated tenant boundary
    category: str               # "technical_explanation", "architecture"
    metadata: dict[str, Any]    # Optimization metrics
```

#### Cache Eviction & Lifecycle Policy:
- **Time-To-Live (TTL)**: Entries expire after `default_ttl` (1 hour). Stale entries are pruned automatically upon lookup.
- **Capacity Bound**: Capped at `max_entries=1000`. When the limit is reached, the oldest unaccessed entry is evicted (`_cache.popitem(last=False)`).
- **Thread Safety**: All reads and writes are protected by an `RLock` (`self._lock`).

---

### 4. Telemetry, Avoided Latency & Cost Tracking (`app/optimization/usage_collector.py`)
Every query evaluated by AIRLOCK produces a `RequestEfficiencyRecord`:

| Metric | Fresh Generation (Cache Miss) | Repeated Prompt (Cache Hit) | Ineligible Tool Request |
| :--- | :--- | :--- | :--- |
| **Cache Status** | `MISS` | `HIT` | `INELIGIBLE` |
| **Response Latency** | `180ms – 450ms` | **`< 25ms` (90%+ latency drop)** | `150ms – 300ms` |
| **Input Tokens Billed** | Standard pricing | **0 (100% saved)** | Standard pricing |
| **Output Tokens Billed**| Standard pricing | **0 (100% saved)** | Standard pricing |
| **Avoided Cost** | `$0.00` | **Calculated per model tier** | `$0.00` (Security Enforced) |
| **Audit Action** | Model invoked | **Served from local LRU vault** | Inspected by PEP/PDP policy |

The frontend **Efficiency Engine** tab aggregates this telemetry in real time:
- Total Requests & Hit Rate (%)
- Total Avoided Tokens & Estimated Enterprise Cost Avoidance ($)
- Live Comparison Histogram (Fresh vs Cached latency)

---

## Part 2: Important Files Reference Guide for Judges

When judges ask for technical proof or code architecture, refer to this precise index:

### 1. Zero-Trust Gateway & Policy Enforcement (PEP & PDP)
| Component | File Path | What to Show Judges |
| :--- | :--- | :--- |
| **Gateway Interceptor (PEP)** | [`app/gateway/gateway_server.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/gateway/gateway_server.py) | `forward()` method: intercepts downstream stdio tool call, evaluates JSON policy, checks SHA-256 fingerprint, halts denied calls before upstream session is opened. |
| **Deterministic Policy Engine** | [`app/policies/json_policy.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/policies/json_policy.py) | `authorize()` method: evaluates allowed tools, argument constraints, and default-deny effect. |
| **Access Control (3 Levels)** | [`app/security/access_control.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/security/access_control.py) | `evaluate_protected_operation()`: routes operations into `ALLOW`, `REQUIRE_APPROVAL`, or `DENY`. Catches path traversal (`../`) and credential exfiltration. |
| **Active Policy Configuration** | [`config/policy.json`](file:///c:/Users/Admin/Desktop/hackurity-1/config/policy.json) | The real JSON rules enforced by the gateway. |

---

### 2. Human-in-the-Loop & Replay Prevention
| Component | File Path | What to Show Judges |
| :--- | :--- | :--- |
| **Approval Store & Replay Defense** | [`app/audit/approval_store.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/audit/approval_store.py) | `canonical_request_hash()`: SHA-256 binding of arguments.<br>`create()`: issues `apr_...` single-use ticket with 300s TTL.<br>`consume()`: enforces exactly-once execution and prevents replay. |
| **Multi-Factor Risk Scoring** | [`app/security/risk.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/security/risk.py) | `assess_tool_request()`: calculates risk scores (0–100) based on blast radius, state-change, and target environment. |

---

### 3. Prompt Caching & Token Optimization
| Component | File Path | What to Show Judges |
| :--- | :--- | :--- |
| **Cache Eligibility Guard** | [`app/optimization/cache_eligibility.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/optimization/cache_eligibility.py) | Shows why stateful commands and tools are **never cached**. |
| **SHA-256 Cache Keys** | [`app/optimization/cache_keys.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/optimization/cache_keys.py) | Canonical prompt serialization and tenant-isolated hash generation. |
| **Bounded LRU Cache** | [`app/optimization/cache_interface.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/optimization/cache_interface.py) | Thread-safe `InMemoryResponseCache` with TTL expiry and capacity eviction. |
| **Telemetry & Cost Calculator** | [`app/optimization/cost_calculator.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/optimization/cost_calculator.py)<br>[`app/optimization/usage_collector.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/optimization/usage_collector.py) | Avoided cost formulas for Gemini 2.5 Flash ($0.075 / $0.30 per 1M) and Pro ($1.25 / $5.00 per 1M). |

---

### 4. Official GitHub MCP Server Integration
| Component | File Path | What to Show Judges |
| :--- | :--- | :--- |
| **GitHub MCP Client** | [`app/gateway/github_mcp_client.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/gateway/github_mcp_client.py) | Real connection to `github-mcp-server` via stdio container or safe in-memory fallback. |
| **GitHub Zero-Trust Policy** | [`app/policies/github_policy.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/policies/github_policy.py) | Enforces branch protection on `main`/`master`, allowed repo white-listing, and read/write separation. |
| **Detailed Integration Spec** | [`docs/GITHUB_MCP_INTEGRATION.md`](file:///c:/Users/Admin/Desktop/hackurity-1/docs/GITHUB_MCP_INTEGRATION.md) | Architectural specification of the GitHub MCP mediation boundary. |

---

### 5. Response Inspection & Cryptographic Audit
| Component | File Path | What to Show Judges |
| :--- | :--- | :--- |
| **Response Inspector** | [`app/gateway/response_inspection.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/gateway/response_inspection.py) | Inspects upstream MCP tool output for prompt injection markers, instruction overrides, and secret disclosure. |
| **SQLite Audit Vault** | [`app/audit/sqlite_audit.py`](file:///c:/Users/Admin/Desktop/hackurity-1/app/audit/sqlite_audit.py) | Cryptographically verifiable audit log. Redacts sensitive parameters before storing. |
| **Audit Database File** | `data/sentry_x_audit.db` | Real local SQLite database storing all gateway decisions and correlation IDs. |

---

## Part 3: Live 2-Minute Judge Demo Script

If asked to prove the system live:

1. **Show the Gateway Blocking an Attack (Level 3 - Deny)**:
   - Navigate to **Attack Simulation Lab** (`#sandbox`) in the UI.
   - Click **Run Attack Scenario 1 (Indirect Prompt Injection / Delete DB)**.
   - Show judges the red barrier glow: **Gateway halted the attack at Step 3/5**. Downstream calls = 0.
   - Point to the audit log: `upstream_executed: false`.

2. **Show Dual-Control Approval (Level 2 - Human in the Loop)**:
   - In **AI Assistant** (`#assistant`), select preset: `Restart dev-vm-01`.
   - Show the prompt pausing: `REQUIRE_APPROVAL` ticket generated (`apr_...`).
   - Switch to **Pending Approvals** (`#approvals`).
   - Click **Review & Decide**, verify sanitized arguments, and click **Approve Once**.
   - Show the execution complete and the single-use ticket transition to `consumed`.

3. **Show Prompt Caching & Token Avoidance (Efficiency Engine)**:
   - Open **Efficiency Engine** (`#efficiency`).
   - Show the **Cache Hit Rate** (e.g. 65%), **Avoided Latency** (<25ms vs ~250ms), and **Avoided Cost ($)**.
   - In **AI Assistant**, ask an educational question: `"What is Zero Trust architecture?"`.
   - Notice the badge: `⚡ AIRLOCK INTELLIGENT CACHE HIT` with 0 billed tokens.
