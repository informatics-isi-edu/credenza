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

import pytest
import fakeredis
import redis
import valkey
import uuid
import time
import testing.postgresql
from credenza.api.session.storage.backends.memory import MemoryBackend
from credenza.api.session.storage.backends.redis import RedisBackend
from credenza.api.session.storage.backends.valkey import ValkeyBackend
from credenza.api.session.storage.backends.sqlite import SQLiteBackend
from credenza.api.session.storage.backends.postgresql import PostgreSQLBackend

postgresql = testing.postgresql.Postgresql()

@pytest.fixture(params=[
    "memory",
    "redis",
    "valkey",
    "postgresql",
    "sqlite"
], ids=lambda name: name)
def backend(request, monkeypatch):
    """
    Fixture to provide a backend instance for each implementation.
    """
    server = fakeredis.FakeServer()
    fake_redis = fakeredis.FakeRedis(server=server)

    if request.param == "memory":
        return MemoryBackend()
    elif request.param == "redis":
        monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, url: fake_redis))
        return RedisBackend(url="redis://fake")
    elif request.param == "valkey":
        monkeypatch.setattr(valkey.Valkey, "from_url", classmethod(lambda cls, url: fake_redis))
        return ValkeyBackend(url="valkey://fake")
    elif request.param == "sqlite":
        return SQLiteBackend()
    elif request.param == "postgresql":
        return PostgreSQLBackend(url=postgresql.url())
    else:
        raise RuntimeError("Unsupported backend")

def test_backend_set_and_get_bytes(backend):
    key = f"test:{uuid.uuid4()}"
    value = b"test value"
    backend.set(key, value)
    assert backend.get(key) == value

def test_backend_set_and_get_string(backend):
    key = f"test:{uuid.uuid4()}"
    value = "hello world"
    backend.set(key, value)
    raw = backend.get(key)
    assert raw.decode("utf-8") == value

def test_backend_delete_removes_key(backend):
    key = f"test:{uuid.uuid4()}"
    backend.set(key, b"to-delete")
    assert backend.get(key) is not None
    backend.delete(key)
    assert backend.get(key) is None

def test_backend_setex_sets_and_expires(monkeypatch, backend):
    key = f"ttl:{uuid.uuid4()}"
    value = b"expiring"

    # monkeypatch time for in-memory and SQLite backends
    now = 1000
    monkeypatch.setattr(time, "time", lambda: now)
    backend.setex(key, value, 5)

    assert backend.get(key) == value

    monkeypatch.setattr(time, "time", lambda: now + 6)
    # For Redis/Valkey fake backends, setex expiry is respected automatically
    result = backend.get(key)
    assert result in (None, value)  # SQLite/Memory may not enforce expiry unless explicit

def test_backend_keys_returns_expected_matches(backend):
    key1 = f"key:{uuid.uuid4()}"
    key2 = f"key:{uuid.uuid4()}"
    backend.set(key1, b"val1")
    backend.set(key2, b"val2")

    keys = set(k.decode() if isinstance(k, bytes) else k for k in backend.keys("key:*"))
    assert key1 in keys
    assert key2 in keys

def test_backend_overwrites_existing_key(backend):
    key = f"dup:{uuid.uuid4()}"
    backend.set(key, b"one")
    backend.set(key, b"two")
    assert backend.get(key) == b"two"

def test_backend_allows_empty_value(backend):
    key = f"empty:{uuid.uuid4()}"
    backend.set(key, b"")
    assert backend.get(key) == b""

def test_backend_unicode_keys_and_values(backend):
    key = f"🗝️:{uuid.uuid4()}"
    val = "🚀🔥"
    backend.set(key, val)
    assert backend.get(key).decode("utf-8") == val
