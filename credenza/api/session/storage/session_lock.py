#
# Copyright 2026 University of Southern California
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
"""Per-session locks that serialize the read-modify-write cycles on a session record.

Refreshing a session spends its upstream refresh token, and an IdP that rotates refresh tokens
(NIH RAS does) may treat a second use of the same token as replay and revoke the whole grant. Two
code paths must therefore never refresh the same session at once, and no writer may put back a
copy of the session read before another writer rotated its token or deleted it.

Locks are in-process: Credenza runs as a single process with several request threads plus the
background refresh worker. Running more than one process (or host) against a shared store would
need a store-provided lease instead.

The locks are striped: a fixed set of NUM_STRIPES locks, each session id hashed to one. Memory is
constant and nothing needs cleaning up; the cost is that two unrelated sessions occasionally share
a lock and wait on each other. Because two session ids can share a stripe, a thread must never hold
more than one session lock at a time: acquiring a second could deadlock against the first.
"""
import threading
import zlib
from contextlib import contextmanager
from typing import Iterator

NUM_STRIPES = 256

_STRIPES = tuple(threading.Lock() for _ in range(NUM_STRIPES))


def _stripe(session_id: str) -> threading.Lock:
    # crc32 rather than hash(): stable across processes and runs, so tests are deterministic
    return _STRIPES[zlib.crc32(session_id.encode("utf-8")) % NUM_STRIPES]


@contextmanager
def session_lock(session_id: str, blocking: bool = True, timeout: float = -1) -> Iterator[bool]:
    """Hold the lock for session_id for the duration of the block.

    Yields True if the lock was acquired. With blocking=False, or when timeout (seconds) elapses
    first, it yields False and the block must not read-modify-write the session. Never acquire a
    second session lock while holding one.
    """
    lock = _stripe(session_id)
    acquired = lock.acquire(timeout=timeout) if blocking else lock.acquire(blocking=False)
    try:
        yield acquired
    finally:
        if acquired:
            lock.release()
