"""Replay protection / at-most-once nonce stores for SinkGate.

Redis Streams consumer groups provide at-least-once delivery (e.g. via
``XAUTOCLAIM`` after worker restarts or network partitions). ``ReplayStore``
consumes each envelope's unique ``nonce`` atomically *before* tool execution,
yielding **at-most-once** execution semantics for side-effecting sinks:
- If the tool fails or the worker crashes after marking the nonce, redelivery
  is blocked (fail-closed) rather than risking duplicate execution.
- If the replay store backend (Redis) is unreachable, ``ReplayStoreError`` is
  raised and ``SinkGate`` fails closed without invoking the tool.
"""

from __future__ import annotations

import heapq
import threading
import time
from typing import Protocol

import redis


class ReplayStoreError(RuntimeError):
    """Raised when the backing replay store is unavailable or returns an error."""


class ReplayStore(Protocol):
    """Protocol for atomic nonce tracking at the sink."""

    def check_and_mark(self, scope: str, nonce: str, ttl_seconds: int) -> bool:
        """Atomically record ``(scope, nonce)`` for at least ``ttl_seconds`` if unseen.

        Returns ``True`` if fresh and now marked, or ``False`` if already seen.
        Raises ``ReplayStoreError`` if the backing store cannot be reached.
        """


class RedisReplayStore:
    """Distributed atomic replay guard backed by Redis ``SET ... NX EX``."""

    def __init__(
        self,
        client: redis.Redis,
        *,
        prefix: str = "shield:replay:",
        default_ttl_seconds: int = 3600,
    ) -> None:
        self.client = client
        self.prefix = prefix
        self.default_ttl_seconds = default_ttl_seconds

    def check_and_mark(self, scope: str, nonce: str, ttl_seconds: int | None = None) -> bool:
        ttl = max(int(self.default_ttl_seconds if ttl_seconds is None else ttl_seconds), 1)
        key = f"{self.prefix}{scope}:{nonce}"
        try:
            acquired = self.client.set(key, "1", nx=True, ex=ttl)
        except redis.exceptions.RedisError as exc:
            raise ReplayStoreError(f"Redis replay store unavailable: {exc}") from exc
        return bool(acquired)


class InMemoryReplayStore:
    """Thread-safe in-process replay guard with O(1) amortized min-heap expiration."""

    def __init__(self, *, default_ttl_seconds: int = 3600) -> None:
        self.default_ttl_seconds = default_ttl_seconds
        self._lock = threading.Lock()
        self._seen: dict[tuple[str, str], float] = {}
        self._expiry_heap: list[tuple[float, tuple[str, str]]] = []
        self.last_ttl_seconds: int | None = None

    def _prune(self, now: float) -> None:
        while self._expiry_heap and self._expiry_heap[0][0] <= now:
            exp, key = heapq.heappop(self._expiry_heap)
            if self._seen.get(key) == exp:
                del self._seen[key]

    def check_and_mark(self, scope: str, nonce: str, ttl_seconds: int | None = None) -> bool:
        now = time.monotonic()
        ttl = max(int(self.default_ttl_seconds if ttl_seconds is None else ttl_seconds), 1)
        entry_key = (scope, nonce)
        with self._lock:
            self._prune(now)
            self.last_ttl_seconds = ttl
            existing_exp = self._seen.get(entry_key)
            if existing_exp is not None and existing_exp > now:
                return False
            expires_at = now + ttl
            self._seen[entry_key] = expires_at
            heapq.heappush(self._expiry_heap, (expires_at, entry_key))
            return True
