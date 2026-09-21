"""Per-client token bucket. In-memory, so it is per-process: with several workers,
move this to Redis (an atomic counter with expiry per client is enough).

`cost` lets expensive requests (a message with several links to open) drain more tokens
than cheap ones."""
from __future__ import annotations

import math
import threading
import time


class TokenBucket:
    def __init__(self, per_minute: int, burst: int, clock=time.monotonic):
        self.rate = per_minute / 60.0
        self.capacity = float(burst)
        self._clock = clock
        self._state: dict[str, tuple[float, float]] = {}  # key -> (tokens, last_seen)
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> tuple[bool, int]:
        """Return (allowed, retry_after_seconds)."""
        cost = min(cost, self.capacity)  # a request costing more than the bucket could never pass
        now = self._clock()
        with self._lock:
            if len(self._state) > 10_000:  # bound memory under a flood of distinct clients
                cutoff = now - 3600
                self._state = {k: v for k, v in self._state.items() if v[1] > cutoff}
            tokens, last = self._state.get(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= cost:
                self._state[key] = (tokens - cost, now)
                return True, 0
            self._state[key] = (tokens, now)
            return False, max(1, math.ceil((cost - tokens) / self.rate))
