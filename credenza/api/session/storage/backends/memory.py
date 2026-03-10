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
import fnmatch
import logging
import threading
from typing import List, Optional, Union
from .base import StorageBackend

logger = logging.getLogger(__name__)


class MemoryBackend(StorageBackend):
    """
    An in-memory KV backend with TTL support.

    - Values are stored as bytes internally.
    - A lock protects concurrent access so `consume()` can be implemented
      atomically (delete-and-return).
    """
    def __init__(self, **kwargs):
        # key -> (bytes_value, expiration timestamp|None)
        self._store = {}
        self._lock = threading.RLock()

    def setex(self, key: str, value: Union[str, bytes], ttl: int) -> None:
        if value is None:
            raise ValueError("value cannot be None")
        expiration = int(time.time()) + int(ttl)
        blob = value if isinstance(value, (bytes, bytearray)) else str(value).encode()
        with self._lock:
            self._store[key] = (bytes(blob), expiration)

    def set(self, key: str, value: Union[str, bytes]) -> None:
        if value is None:
            raise ValueError("value cannot be None")
        blob = value if isinstance(value, (bytes, bytearray)) else str(value).encode()
        with self._lock:
            self._store[key] = (bytes(blob), None)  # None for no expiry

    def _purge_if_expired_locked(self, key: str) -> None:
        """Helper: assumes lock is held. Remove key if expired."""
        entry = self._store.get(key)
        if not entry:
            return
        _, expiration = entry
        if expiration is not None and int(time.time()) >= expiration:
            # expired -> remove
            self._store.pop(key, None)

    def get(self, key: str) -> Optional[bytes]:
        with self._lock:
            self._purge_if_expired_locked(key)
            entry = self._store.get(key)
            if not entry:
                return None
            value, _ = entry
            return bytes(value)

    def consume(self, key: str) -> Optional[bytes]:
        """
        Atomically delete-and-return the value for `key`.
        Returns bytes or None if missing/expired.
        """
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            value, expiration = entry
            if expiration is not None and int(time.time()) >= expiration:
                # expired -> remove and behave as missing
                self._store.pop(key, None)
                return None
            # present and not expired -> remove and return
            self._store.pop(key, None)
            return bytes(value)

    def delete(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)

    def keys(self, pattern: str) -> List[str]:
        now = int(time.time())
        with self._lock:
            # purge expired keys first
            for k in list(self._store.keys()):
                _, expiration = self._store[k]
                if expiration is not None and now >= expiration:
                    self._store.pop(k, None)
            # fnmatch for glob pattern matching
            return fnmatch.filter(list(self._store.keys()), pattern)

    def scan_iter(self, pattern: str):
        for key in self.keys(pattern):
            yield key

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def ttl(self, key: str) -> int:
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return -2  # key missing
            _, expiration = entry
            if expiration is None:
                return -1  # no expiration
            now = int(time.time())
            remaining = expiration - now
            if remaining < 0:
                # expired; clean up
                self._store.pop(key, None)
                return -2
            return int(remaining)
