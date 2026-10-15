"""Cache interface and in-memory bounded LRU implementation for AIRLOCK."""

from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class CacheEntry:
    key: str
    content: str
    model: str
    input_tokens: int
    output_tokens: int
    created_at: float
    expires_at: float
    tenant_id: str
    category: str
    metadata: dict[str, Any]

    def is_expired(self) -> bool:
        return time.time() > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class BaseResponseCache(ABC):
    """Abstract interface for AIRLOCK response caching."""

    @abstractmethod
    def get(self, key: str) -> CacheEntry | None:
        """Retrieve an entry if present and unexpired."""

    @abstractmethod
    def set(
        self,
        key: str,
        content: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        ttl_seconds: int = 3600,
        tenant_id: str = "default",
        category: str = "general",
        metadata: dict[str, Any] | None = None,
    ) -> CacheEntry:
        """Store an entry with a bounded TTL."""

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Remove a single entry."""

    @abstractmethod
    def invalidate_all(self, tenant_id: str | None = None) -> int:
        """Invalidate all entries or all entries for a specific tenant."""

    @abstractmethod
    def stats(self) -> dict[str, Any]:
        """Return cache health, hit rate, and capacity metrics."""


class InMemoryResponseCache(BaseResponseCache):
    """Thread-safe, bounded LRU in-memory response cache."""

    def __init__(self, max_entries: int = 1000, default_ttl: int = 3600) -> None:
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def get(self, key: str) -> CacheEntry | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry.is_expired():
                del self._cache[key]
                self._misses += 1
                return None
            # Move to end for LRU order
            self._cache.move_to_end(key)
            self._hits += 1
            return entry

    def set(
        self,
        key: str,
        content: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        ttl_seconds: int = 3600,
        tenant_id: str = "default",
        category: str = "general",
        metadata: dict[str, Any] | None = None,
    ) -> CacheEntry:
        now = time.time()
        ttl = ttl_seconds if ttl_seconds > 0 else self.default_ttl
        entry = CacheEntry(
            key=key,
            content=content,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            created_at=now,
            expires_at=now + ttl,
            tenant_id=tenant_id,
            category=category,
            metadata=metadata or {},
        )
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
            self._cache[key] = entry
            # Enforce max entries via LRU eviction
            while len(self._cache) > self.max_entries:
                self._cache.popitem(last=False)
                self._evictions += 1
        return entry

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False

    def invalidate_all(self, tenant_id: str | None = None) -> int:
        with self._lock:
            if tenant_id is None:
                count = len(self._cache)
                self._cache.clear()
                return count
            keys_to_remove = [k for k, v in self._cache.items() if v.tenant_id == tenant_id]
            for k in keys_to_remove:
                del self._cache[k]
            return len(keys_to_remove)

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total_lookups = self._hits + self._misses
            hit_rate = (self._hits / total_lookups * 100) if total_lookups > 0 else 0.0
            return {
                "active_entries": len(self._cache),
                "max_entries": self.max_entries,
                "hits": self._hits,
                "misses": self._misses,
                "total_lookups": total_lookups,
                "hit_rate_pct": round(hit_rate, 1),
                "evictions": self._evictions,
                "backend": "in_memory_lru",
            }
