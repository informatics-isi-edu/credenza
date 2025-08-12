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
import redis
import valkey
import fakeredis
import testing.postgresql
from types import SimpleNamespace
from credenza.api.util import AESGCMCodec
from credenza.api.session.storage.session_store import SessionStore, SessionData
from credenza.api.session.storage.backends.memory import MemoryBackend
from credenza.api.session.storage.backends.redis import RedisBackend
from credenza.api.session.storage.backends.valkey import ValkeyBackend
from credenza.api.session.storage.backends.sqlite import SQLiteBackend
from credenza.api.session.storage.backends.postgresql import PostgreSQLBackend

postgresql = testing.postgresql.Postgresql()

@pytest.fixture(params=[
    "redis",
    "redis-encrypted",
    "valkey",
    "valkey-encrypted",
    "sqlite",
    "sqlite-encrypted",
    "postgresql",
    "postgresql-encrypted",
    "memory",
    "memory-encrypted"],
    ids=lambda val: val, scope="function")
def store(request, monkeypatch):

    backend_type = request.param
    server = fakeredis.FakeServer()
    fake_redis = fakeredis.FakeRedis(server=server)

    if backend_type.startswith("redis"):
        monkeypatch.setattr(
            redis.Redis, "from_url",
            classmethod(lambda cls, url: fake_redis)
        )
        backend = RedisBackend(url="redis://fake")
    elif backend_type.startswith("valkey"):
        monkeypatch.setattr(
            valkey.Valkey, "from_url",
            classmethod(lambda cls, url: fake_redis)
        )
        backend = ValkeyBackend(url="valkey://fake")
    elif backend_type.startswith("sqlite"):
        backend = SQLiteBackend()
    elif backend_type.startswith("postgresql"):
        backend = PostgreSQLBackend(url=postgresql.url())
    elif backend_type.startswith("memory"):
        backend = MemoryBackend()
    else:
        raise RuntimeError(f"Unknown backend {backend_type}")

    return SessionStore(
        backend=backend,
        ttl=2100,
        crypto_codec=AESGCMCodec("supersecretvalue") if "-encrypted" in backend_type else None
    )

def test_create_and_get_session(store):
    sid = "sess1"
    store.create_session(
        session_id=sid,
        id_token="idtok",
        access_token="atok",
        refresh_token="rtok",
        userinfo={"sub": "u1"},
        realm="realm1"
    )
    data = store.get_session_data(sid)
    assert isinstance(data, SessionData)
    assert data.id_token == "idtok"
    assert data.userinfo["sub"] == "u1"


def test_get_session_by_session_key(store):
    sid = "sess3"
    skey,_  = store.create_session(
        session_id=sid,
        id_token="idtok",
        access_token="token123",
        refresh_token="rtok",
        userinfo={},
        realm="realm"
    )
    sid, session = store.get_session_by_session_key(skey)
    assert isinstance(session, SessionData)
    assert session.access_token == "token123"

def test_update_and_delete_session(store):
    sid = "sess4"
    store.create_session(
        session_id=sid,
        id_token="id1",
        access_token="tok1",
        refresh_token="rt1",
        userinfo={},
        realm="realm"
    )
    # Fetch, mutate, and update the SessionData
    data = store.get_session_data(sid)
    data.access_token = "tok2"
    store.update_session(sid, data)
    updated = store.get_session_data(sid)
    assert updated.access_token == "tok2"

    # Delete and confirm removal
    store.delete_session(sid)
    assert store.get_session_data(sid) is None

def test_list_session_ids_and_get_ttl(frozen_time, store):
    # Create two sessions
    store.create_session(session_id="a", id_token="i", access_token="a", refresh_token="r", userinfo={}, realm="realm")
    store.create_session(session_id="b", id_token="i", access_token="a", refresh_token="r", userinfo={}, realm="realm")
    ids = store.list_session_ids()
    assert "a" in set(ids)

    # TTL returns the dummy value
    assert store.get_ttl("a") == 2100
    assert store.get_ttl("b") == 2100

def test_nonce_lifecycle(store):
    # store_nonce and get_nonce should round-trip the JSON-able object
    store.store_nonce("n1", "abc123")
    assert store.get_nonce("n1") == "abc123"
    store.delete_nonce("n1")
    assert store.get_nonce("n1") is None

def test_device_flow_mappings(store):
    store.set_device_flow("dev1", "abc123", store.ttl)
    assert store.get_device_flow("dev1") == "abc123"

    store.set_usercode_mapping("user1", "dev1", 600)
    assert store.get_device_code_for_usercode("user1") == "dev1"

def test_get_session_data_corrupted_json(monkeypatch, store):
    bad_id = "badjson"
    key = store._key(bad_id)
    # Set raw non-JSON bytes
    store.backend.setex(key, b"not a valid json", store.ttl)
    # Calling get_session_data should return None and delete the key
    result = store.get_session_data(bad_id)
    assert result is None
    # The backend key must have been deleted
    assert store.backend.get(key) is None

def test_get_session_data_decryption_failure(monkeypatch, store):
    # Enable a fake crypto_codec that always fails to decrypt
    fake_codec = SimpleNamespace(
        decrypt=lambda payload: None
    )
    store.crypto_codec = fake_codec

    # Manually jam any payload (will be fed to decrypt and return None)
    bad_id = "bad-encrypt"
    key = store._key(bad_id)
    store.backend.setex(key,b"garbage", store.ttl)
    # Now get_session_data should catch the decryption failure,
    # delete the key, and return None
    result = store.get_session_data(bad_id)
    assert result is None
    assert store.backend.get(key) is None
