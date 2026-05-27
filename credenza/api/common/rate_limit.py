#
# Copyright 2025 University of Southern California
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import time
import math
import random
import threading

class FixedWindowJitterLimiter:
    """
    In-memory fixed-window rate limiter with per-key jittered boundaries.
    - Process-local (per gunicorn worker / mod_wsgi process)
    - Thread-safe
    - Reusable across endpoints
    """

    def __init__(self, limit, window_sec, *, max_keys=50_000, idle_ttl_sec=3600, seed=None):
        if limit <= 0 or window_sec <= 0:
            raise ValueError("limit and window_sec must be positive")
        self.limit = int(limit)
        self.window = int(window_sec)
        self.max_keys = int(max_keys)
        self.idle_ttl = int(idle_ttl_sec)

        self._count = {}      # key -> (window_id:int, count:int)
        self._jitter = {}     # key -> int offset in [0, window)
        self._last = {}       # key -> monotonic last-seen
        self._rng = random.Random(seed or int(time.time() * 1e6))
        self._lock = threading.Lock()


    def allow(self, key, now=None):
        """
        Consume 1 request for 'key' in the current jittered window.

        Returns (allowed: bool, remaining: int, reset_s: int)
        """
        if not key:
            key = "_"
        now = time.time() if now is None else float(now)
        wid, seconds_left = self._window_id_and_reset(now, key)

        with self._lock:
            self._evict_idle()

            cur_wid, cnt = self._count.get(key, (wid, 0))
            if cur_wid != wid:
                cur_wid, cnt = wid, 0

            allowed = cnt < self.limit
            if allowed:
                cnt += 1

            self._count[key] = (cur_wid, cnt)
            self._last[key] = time.monotonic()

            remaining = max(0, self.limit - cnt)
            reset_s = max(0, int(math.ceil(seconds_left)))
            return allowed, remaining, reset_s

    def headers(self, remaining, reset_s):
        """Standard rate-limit headers for this limiter policy."""
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(max(0, int(remaining))),
            "X-RateLimit-Reset": str(max(0, int(reset_s))),
        }

    def _window_id_and_reset(self, now, key):
        off = self._jitter.get(key)
        if off is None:
            off = self._rng.randrange(self.window)
            self._jitter[key] = off
        shifted = now + off
        wid = int(shifted // self.window)
        seconds_left = ((wid + 1) * self.window) - (shifted % self.window)
        return wid, seconds_left

    def _evict_idle(self):
        # prune idle entries
        cutoff = time.monotonic() - self.idle_ttl
        stale = [k for k, ts in self._last.items() if ts < cutoff]
        for k in stale:
            self._count.pop(k, None)
            self._jitter.pop(k, None)
            self._last.pop(k, None)

        # hard cap as a backstop
        overflow = len(self._count) - self.max_keys
        if overflow > 0:
            for k in list(self._count.keys())[:overflow]:
                self._count.pop(k, None)
                self._jitter.pop(k, None)
                self._last.pop(k, None)
