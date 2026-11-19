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
"""Concurrency between the refresh worker and session deletes, against a real in-memory store."""
import threading
import time
import pytest
from credenza.refresh import refresh_worker as rw
from credenza.api.common.util import end_session, delete_lock_wait
from credenza.api.session.storage.session_lock import session_lock
from credenza.api.session.storage.session_store import SessionType


class SlowTokenEndpoint:
    """OIDC client whose refresh blocks until released, so a test can act mid-refresh."""

    def __init__(self):
        self.calls = 0
        self.started = threading.Event()
        self.release = threading.Event()

    def refresh_access_token(self, refresh_token):
        self.calls += 1
        self.started.set()
        assert self.release.wait(5), "test never released the refresh"
        return {"access_token": "new-at", "refresh_token": "rt-2", "expires_at": int(time.time()) + 1800}


class Factory:
    def __init__(self, client):
        self.client = client

    def get_client(self, realm, **kwargs):
        return self.client


@pytest.fixture
def endpoint(app):
    client = SlowTokenEndpoint()
    app.config["OIDC_CLIENT_FACTORY"] = Factory(client)
    app.config["OIDC_IDP_PROFILES"] = {"test": {"skip_token_revocation": True}}
    return client


@pytest.fixture
def due_device_session(store):
    """A device session whose access token is due for refresh."""
    now = int(time.time())
    sid = store.generate_session_id()
    store.create_session(
        session_id=sid,
        session_type=SessionType.DEVICE,
        access_token="old-at",
        refresh_token="rt-1",
        userinfo={"iss": "https://issuer", "sub": "u1"},
        realm="test",
        metadata={"allow_automatic_refresh": True, "access_token_expires_at": now - 1},
        expires_at=now + 3600,
    )
    return sid


def _one_worker_pass(app, monkeypatch):
    def stop(_):
        raise StopIteration
    monkeypatch.setattr(rw.time, "sleep", stop)
    with app.app_context():
        with pytest.raises(StopIteration):
            rw.run_refresh_worker(app)


def test_worker_skips_a_session_another_thread_holds(app, store, endpoint, due_device_session, monkeypatch):
    endpoint.release.set()
    with session_lock(due_device_session):
        _one_worker_pass(app, monkeypatch)
    assert endpoint.calls == 0
    assert store.get_session_data(due_device_session).refresh_token == "rt-1"

    _one_worker_pass(app, monkeypatch)
    assert endpoint.calls == 1
    assert store.get_session_data(due_device_session).refresh_token == "rt-2"


def test_worker_deletes_orphaned_record_without_calling_the_idp(app, store, endpoint, due_device_session,
                                                                 monkeypatch):
    endpoint.release.set()
    store.unmap_session(session_id=due_device_session)
    _one_worker_pass(app, monkeypatch)
    assert endpoint.calls == 0
    assert store.get_session_data(due_device_session) is None


def test_logout_during_refresh_waits_and_leaves_no_session(app, store, endpoint, due_device_session):
    sid = due_device_session
    session = store.get_session_data(sid)
    errors = []

    def worker_step():
        try:
            with app.app_context():
                with session_lock(sid, blocking=False) as locked:
                    assert locked
                    rw._refresh_session(app, store, sid)
        except Exception as e:  # surfaced to the main thread below
            errors.append(e)

    def logout():
        try:
            with app.app_context():
                end_session(sid, session)
        except Exception as e:
            errors.append(e)

    refresher = threading.Thread(target=worker_step)
    refresher.start()
    assert endpoint.started.wait(5)

    deleter = threading.Thread(target=logout)
    deleter.start()
    deleter.join(0.3)
    assert deleter.is_alive(), "logout should wait for the in-flight refresh"

    endpoint.release.set()
    refresher.join(5)
    deleter.join(5)
    assert not errors, errors
    assert endpoint.calls == 1
    assert store.get_session_data(sid) is None
    assert store.get_session_key_for_session_id(sid) is None


def test_update_session_refuses_to_resurrect_a_deleted_session(app, store, due_device_session):
    stale_copy = store.get_session_data(due_device_session)
    store.delete_session(due_device_session)
    assert store.update_session(due_device_session, stale_copy) == (None, None)
    assert store.get_session_data(due_device_session) is None


def test_delete_wait_follows_the_realm_idp_timeout(app):
    app.config["OIDC_IDP_PROFILES"] = {"slow": {"http_timeout": 40}, "default_timeout": {}}
    with app.app_context():
        assert delete_lock_wait("slow") == 2 * 40 + 5
        assert delete_lock_wait("default_timeout") == 2 * 15 + 5
        assert delete_lock_wait("unknown_realm") == 2 * 15 + 5
