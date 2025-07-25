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
import os
import sqlite3
import logging
import time
import fnmatch
import threading
from typing import Optional, List, Iterable, Union

logger = logging.getLogger(__name__)


class SQLiteBackend:
    """
    A simple SQLite-based key-value store with TTL support and thread-local SQLite connections.
    """
    def __init__(self, url: str = ":memory:", idle_timeout: int = 60):
        self.db_path = url if url else os.path.expanduser("~/credenza-sqlite.db")
        logger.debug(f"Using SQLite database: {self.db_path}")
        if self.db_path != ":memory:" and not os.path.isdir(os.path.dirname(self.db_path)):
            os.makedirs(os.path.dirname(self.db_path))

        self.idle_timeout = idle_timeout
        self.local = threading.local()

    def _get_conn(self):
        now = time.time()
        conn = getattr(self.local, "conn", None)
        ts = getattr(self.local, "last_used", 0)

        if conn is not None and (now - ts) > self.idle_timeout:
            # Close stale connection
            try:
                conn.close()
            except Exception:
                pass
            conn = None

        if conn is None:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS credenza (
                    key TEXT PRIMARY KEY,
                    value BLOB,
                    expires_at REAL
                )
            """)
            conn.commit()
            self.local.conn = conn

        self.local.last_used = now
        return conn

    def close(self):
        """
        Close the SQLite connection associated with the current thread, if any.
        """
        conn = getattr(self.local, "conn", None)
        if conn is not None:
            logger.debug(f"Closing SQLite connection to {self.db_path} in thread {threading.get_ident()}")
            conn.close()
            del self.local.conn
            del self.local.last_used


    def setex(self, key: str, value: Union[str, bytes], ttl: int) -> None:
        expires_at = time.time() + ttl
        blob = value if isinstance(value, (bytes, bytearray)) else value.encode()
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO credenza (key, value, expires_at)
            VALUES (?, ?, ?)
        """, (key, blob, expires_at))
        conn.commit()

    def get(self, key: str) -> Optional[bytes]:
        conn = self._get_conn()
        cur = conn.execute("""
            SELECT value, expires_at FROM credenza WHERE key = ?
        """, (key,))
        row = cur.fetchone()
        if not row:
            return None
        value, expires_at = row
        if expires_at is not None and time.time() >= expires_at:
            self.delete(key)
            return None
        return value

    def delete(self, key: str) -> None:
        conn = self._get_conn()
        conn.execute("DELETE FROM credenza WHERE key = ?", (key,))
        conn.commit()

    def keys(self, pattern: str) -> List[str]:
        conn = self._get_conn()
        cur = conn.execute("SELECT key, expires_at FROM credenza")
        now = time.time()
        result = []
        for key, expires_at in cur:
            if expires_at is not None and now >= expires_at:
                self.delete(key)
                continue
            if fnmatch.fnmatch(key, pattern):
                result.append(key)
        return result

    def scan_iter(self, pattern: str) -> Iterable[str]:
        for key in self.keys(pattern):
            yield key

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def ttl(self, key: str) -> int:
        conn = self._get_conn()
        cur = conn.execute("""
            SELECT expires_at FROM credenza WHERE key = ?
        """, (key,))
        row = cur.fetchone()
        if not row:
            return -2  # key does not exist
        expires_at, = row
        if expires_at is None:
            return -1  # no TTL set
        remaining = int(expires_at - time.time())
        return remaining if remaining >= 0 else -2

    def set(self, key: str, value: Union[str, bytes]) -> None:
        blob = value if isinstance(value, (bytes, bytearray)) else value.encode()
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO credenza (key, value, expires_at)
            VALUES (?, ?, ?)
        """, (key, blob, None))
        conn.commit()
