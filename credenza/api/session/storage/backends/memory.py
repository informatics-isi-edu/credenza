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
from typing import List, Optional, Union
from .base import StorageBackend

logger = logging.getLogger(__name__)


class MemoryBackend(StorageBackend):
    """
    An in-memory KV backend with TTL support.
    """
    def __init__(self, **kwargs):
        # key -> (value, expiration timestamp)
        self._store = {}

    def setex(self, key: str, value: Union[str, bytes], ttl: int) -> None:
        expiration = time.time() + ttl
        if not value:
            raise ValueError("value cannot be None")
        self._store[key] = (value, expiration)

    def set(self, key: str, value: Union[str, bytes]) -> None:
        self._store[key] = (value, None)  # None for expiration means no expiry

    def get(self, key: str) -> Optional[bytes]:
        entry = self._store.get(key)
        if not entry:
            return None
        value, expiration = entry
        # If expiration is None, it's permanent storage
        if expiration is not None:
            now = time.time()
            if now >= expiration:
                # expired
                del self._store[key]
                return None
        return value if isinstance(value, bytes) else value.encode()

    def delete(self, key: str) -> None:
        self._store.pop(key, None)

    def keys(self, pattern: str) -> List[str]:
        now = time.time()
        # purge expired keys first
        for k in list(self._store.keys()):
            _, expiration = self._store[k]
            # Only check expiration if it's not None (permanent storage)
            if expiration is not None and now >= expiration:
                del self._store[k]
        # fnmatch for glob pattern matching
        return fnmatch.filter(list(self._store.keys()), pattern)

    def scan_iter(self, pattern: str):
        for key in self.keys(pattern):
            yield key

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def ttl(self, key: str) -> int:
        entry = self._store.get(key)
        if not entry:
            return -2  # key missing
        _, expiration = entry
        # If expiration is None, it's permanent storage
        if expiration is None:
            return -1  # no expiration
        now = time.time()
        remaining = expiration - now
        if remaining < 0:
            # expired; clean up
            del self._store[key]
            return -2
        return int(remaining)
