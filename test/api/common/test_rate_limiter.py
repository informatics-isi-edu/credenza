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
import math

from credenza.api.common.rate_limit import FixedWindowJitterLimiter

def test_allow_within_limit_and_block_after():
    limiter = FixedWindowJitterLimiter(limit=3, window_sec=60, seed=123)
    t0 = 1_000_000

    # First 3 calls allowed
    for i in range(3):
        allowed, remaining, reset_s = limiter.allow("ip:1.2.3.4", now=t0)
        assert allowed is True
        assert remaining == 3 - (i + 1)
        assert reset_s > 0

    # 4th call in same window blocks
    allowed, remaining, reset_s = limiter.allow("ip:1.2.3.4", now=t0)
    assert allowed is False
    assert remaining == 0
    assert reset_s > 0

def test_per_key_independence():
    limiter = FixedWindowJitterLimiter(limit=2, window_sec=30, seed=42)
    t0 = 2_000_000

    # Exhaust key A
    assert limiter.allow("A", now=t0)[0] is True
    assert limiter.allow("A", now=t0)[0] is True
    assert limiter.allow("A", now=t0)[0] is False

    # Key B is unaffected
    assert limiter.allow("B", now=t0)[0] is True
    assert limiter.allow("B", now=t0)[0] is True
    assert limiter.allow("B", now=t0)[0] is False

def test_rollover_integer_time():
    limiter = FixedWindowJitterLimiter(limit=2, window_sec=10, seed=99)
    key = "k"
    t0 = 4_000_000

    # Consume both tokens at t0
    assert limiter.allow(key, now=t0)[0] is True
    assert limiter.allow(key, now=t0)[0] is True
    assert limiter.allow(key, now=t0)[0] is False

    # Find the boundary in whole seconds by advancing until we observe reset
    # (Worst case advances <= window_sec steps)
    t = t0
    while True:
        t += 1
        if limiter.allow(key, now=t)[0] is True:
            # We crossed into the next window at time t
            # One token used in new window
            break

    assert limiter.allow(key, now=t)[0] is True  # 2nd token in new window
    assert limiter.allow(key, now=t)[0] is False

def test_headers_shape_and_values():
    limiter = FixedWindowJitterLimiter(limit=5, window_sec=15, seed=7)
    t0 = 4_000_000

    # Make 2 allowed calls
    assert limiter.allow("ip:7.7.7.7", now=t0)[0] is True
    allowed, remaining, reset_s = limiter.allow("ip:7.7.7.7", now=t0)
    assert allowed is True
    assert remaining == 3
    assert reset_s > 0

    # Headers should mirror the policy and remaining/reset
    hdrs = limiter.headers(remaining, reset_s)
    assert hdrs["X-RateLimit-Limit"] == "5"
    assert hdrs["X-RateLimit-Remaining"] == "3"
    assert int(hdrs["X-RateLimit-Reset"]) == math.ceil(reset_s)

def test_unknown_ip_bucketting():
    limiter = FixedWindowJitterLimiter(limit=1, window_sec=5, seed=1)
    t0 = 5_000_000

    # Using "unknown" key should still rate-limit collectively
    assert limiter.allow("ip:_", now=t0)[0] is True
    assert limiter.allow("ip:_", now=t0)[0] is False
