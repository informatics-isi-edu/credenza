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
import psycopg2
import psycopg2.pool
import logging
import time
import fnmatch
from typing import Optional, List, Iterable, Union

logger = logging.getLogger(__name__)

class connection (psycopg2.extensions.connection):
    """Customized pyscopg2 connection factory

    Does idempotent schema initialization and prepares statements for reuse.
    """
    def __init__(self, dsn):
        psycopg2.extensions.connection.__init__(self, dsn)
        logger.debug(f"Initializing new connection for PostgreSQL: dsn={self.dsn}")
        with self.cursor() as cur:
            self._idempotent_ddl(cur)
            self._prepare_stmts(cur)
            self.commit()
        logger.debug(f"Initialization complete")

    def _idempotent_ddl(self, cur):
        cur.execute("""
        CREATE TABLE IF NOT EXISTS credenza (
          key text PRIMARY KEY,
          value bytea NOT NULL,
          expires_at float8
        );
        """)

    def _prepare_stmts(self, cur):
        cur.execute("""
        DEALLOCATE PREPARE ALL;

        PREPARE credenza_session_set(text, bytea, float8) AS
        INSERT INTO credenza (key, value, expires_at)
        VALUES($1, $2, $3)
        ON CONFLICT (key)
        DO UPDATE SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at;

        PREPARE credenza_session_get(text) AS
        SELECT value, expires_at FROM credenza WHERE key = $1;

        PREPARE credenza_session_get_expires(text) AS
        SELECT expires_at FROM credenza WHERE key = $1;

        PREPARE credenza_session_list AS
        SELECT key, expires_at FROM credenza;

        PREPARE credenza_session_delete(text) AS
        DELETE FROM credenza WHERE key = $1;
        """)

class PostgreSQLBackend:
    """
    A simple PostgreSQL-based key-value store with TTL support and pooled psycopg2 connections.
    """
    def __init__(self, url: str = "postgresql:///credenza", idle_timeout: int = 60, trace = False):
        # TODO: figure out what idle_timeout would even mean here with pooling??
        # TODO: add configuration for minconn, maxconn here?
        self.dsn = url
        minconn = 1 # need to keep an idle connection open to really benefit from pool?
        maxconn = 6
        self.pool = psycopg2.pool.ThreadedConnectionPool(minconn, maxconn, dsn=url, connection_factory=connection)
        logger.debug(f"Using threaded connection pool for PostgreSQL: minconn={minconn} maxconn={maxconn} url={self.dsn}")
        self.idle_timeout = idle_timeout
        self.trace = trace

    def _get_conn(self):
        conn = self.pool.getconn()
        if self.trace:
            logger.debug(f"Got pooled connection dsn={conn.dsn} status={conn.status}")
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED)
        return conn

    def _put_conn(self, conn, close=False):
        if conn is not None:
            if self.trace:
                logger.debug(f"Returning connection to pool dsn={conn.dsn} status={conn.status} close={close}")
            self.pool.putconn(conn, close=close)

    def close(self):
        """
        Close the backend and clear resources.
        """
        if self.pool is not None:
            logger.debug(f"Shutting down connection pool for dsn={self.dsn}")
            pool = self.pool
            self.pool = None
            pool.closeall()
            del pool

    def _pooled_execute_stmt(self, sql, params, resultfunc=lambda cur: None):
        """Execute and commit one statement on a pooled connection, returning result of resultfunc applied to cursor.
        """
        conn = None
        error = 'unknown error'
        try:
            conn = self._get_conn()
            with conn.cursor() as cur:
                cur.execute(sql, params)
                result = resultfunc(cur)
                conn.commit()
            self._put_conn(conn)
            conn = None
            return result
        except Exception as e:
            # fall through to finally, but save exception
            error = e
        finally:
            if conn is not None:
                logger.warning(f"Closing pooled connection due to error={error}")
                self._put_conn(conn, close=True)

    def setex(self, key: str, value: Union[str, bytes], ttl: int) -> None:
        expires_at = time.time() + ttl
        blob = value if isinstance(value, (bytes, bytearray)) else value.encode()
        self._pooled_execute_stmt(
            "EXECUTE credenza_session_set(%s, %s, %s);",
            (key, blob, expires_at)
        )

    def get(self, key: str) -> Optional[bytes]:
        row = self._pooled_execute_stmt(
            "EXECUTE credenza_session_get(%s);",
            (key,),
            lambda cur: cur.fetchone()
        )
        if not row:
            return None
        value, expires_at = row
        if expires_at is not None and time.time() >= expires_at:
            self.delete(key)
            return None
        return value.tobytes()

    def delete(self, key: str) -> None:
        self._pooled_execute_stmt(
            "EXECUTE credenza_session_delete(%s);",
            (key,)
        )

    def keys(self, pattern: str) -> List[str]:
        rows = self._pooled_execute_stmt(
            "EXECUTE credenza_session_list;",
            None,
            lambda cur: list(cur)
        )
        now = time.time()
        result = []
        for key, expires_at in rows:
            if expires_at is not None and now >= expires_at:
                self.delete(key)
                continue
            if fnmatch.fnmatch(key, pattern):
                result.append(key)
        # after for loop...
        return result

    def scan_iter(self, pattern: str) -> Iterable[str]:
        for key in self.keys(pattern):
            yield key

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def ttl(self, key: str) -> int:
        row = self._pooled_execute_stmt(
            "EXECUTE credenza_session_get_expires(%s);",
            (key,),
            lambda cur: cur.fetchone()
        )
        if not row:
            return -2  # key does not exist
        expires_at, = row
        if expires_at is None:
            return -1  # no TTL set
        remaining = int(expires_at - time.time())
        return remaining if remaining >= 0 else -2

    def set(self, key: str, value: Union[str, bytes]) -> None:
        blob = value if isinstance(value, (bytes, bytearray)) else value.encode()
        row = self._pooled_execute_stmt(
            "EXECUTE credenza_session_set(%s, %s, %s);",
            (key, blob, None)
        )
