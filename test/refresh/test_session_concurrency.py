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
from credenza.rest import session as sm
from credenza.api.common.util import end_session, delete_lock_wait
from credenza.api.session.storage import session_lock as sl
from credenza.api.session.storage.session_lock import session_lock
from credenza.api.session.augmentation.base_provider import EnrichmentResult
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



# --- PUT /session and re-augmentation ---------------------------------------------------------

class RecordingProvider:
    """Augmentation provider that records each call, and whether the session lock was held."""

    def __init__(self, sid, on_enrich=None):
        self.sid = sid
        self.calls = 0
        self.lock_held_during_call = []
        self.on_enrich = on_enrich

    def enrich_userinfo(self, userinfo, additional_tokens):
        self.calls += 1
        self.lock_held_during_call.append(sl._stripe(self.sid).locked())
        if self.on_enrich:
            self.on_enrich()
        userinfo["roles"] = ["tag:example.org,2026:role/Member"]
        return EnrichmentResult(enriched=True)

    def build_identities(self, userinfo):
        return {}


@pytest.fixture
def web(app):
    if "session" not in app.blueprints:
        app.register_blueprint(sm.session_blueprint)
    return app.test_client()


def _device_session(store, *, token_due):
    now = int(time.time())
    sid = store.generate_session_id()
    skey, _ = store.create_session(
        session_id=sid,
        session_type=SessionType.DEVICE,
        access_token="old-at",
        refresh_token="rt-1",
        userinfo={"iss": "https://issuer", "sub": "u1"},
        realm="test",
        metadata={"allow_automatic_refresh": True,
                  "access_token_expires_at": now - 1 if token_due else now + 3600},
        expires_at=now + 3600,
    )
    return sid, skey


def _bearer(skey):
    return {"Authorization": f"Bearer {skey}"}


def test_legacy_put_refreshes_due_token_but_does_not_reaugment(app, store, endpoint, web):
    endpoint.release.set()
    app.config["ENABLE_LEGACY_API"] = True
    sid, skey = _device_session(store, token_due=True)
    provider = RecordingProvider(sid)
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = {"test": provider}

    resp = web.put("/session", headers=_bearer(skey))
    assert resp.status_code == 200
    assert endpoint.calls == 1
    assert store.get_session_data(sid).refresh_token == "rt-2"
    assert provider.calls == 0


def test_explicit_refresh_upstream_reaugments_with_the_lock_released(app, store, endpoint, web):
    endpoint.release.set()
    sid, skey = _device_session(store, token_due=False)
    provider = RecordingProvider(sid)
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = {"test": provider}

    resp = web.put("/session?refresh_upstream=true", headers=_bearer(skey))
    assert resp.status_code == 200
    assert provider.calls == 1
    assert provider.lock_held_during_call == [False]
    assert store.get_session_data(sid).userinfo["roles"] == ["tag:example.org,2026:role/Member"]


def test_nested_put_during_reaugmentation_does_not_wait(app, store, endpoint, web):
    # The ERMrest role provider queries ERMrest as the user, and ERMrest looks the session up with
    # PUT /session. Simulate that nested call from inside augmentation: it must not block.
    endpoint.release.set()
    app.config["ENABLE_LEGACY_API"] = True
    sid, skey = _device_session(store, token_due=False)
    nested = []

    def nested_put():
        started = time.monotonic()
        nested.append((web.put("/session", headers=_bearer(skey)).status_code, time.monotonic() - started))

    provider = RecordingProvider(sid, on_enrich=nested_put)
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = {"test": provider}

    resp = web.put("/session?refresh_upstream=true", headers=_bearer(skey))
    assert resp.status_code == 200
    assert provider.calls == 1, "the nested legacy PUT must not re-run augmentation"
    (status, elapsed), = nested
    assert status == 200
    assert elapsed < 1.0


def test_device_put_answers_without_writing_when_the_lock_is_busy(app, store, endpoint, web, monkeypatch):
    monkeypatch.setattr(sm, "SHORT_LOCK_WAIT", 0.05)
    sid, skey = _device_session(store, token_due=False)
    before = store.get_session_data(sid).updated_at
    with session_lock(sid):
        resp = web.put("/session", headers=_bearer(skey))
    assert resp.status_code == 200
    assert store.get_session_data(sid).updated_at == before


def test_browser_put_never_takes_the_session_lock(app, store, web):
    sid = store.generate_session_id()
    skey, _ = store.create_session(session_id=sid, session_type=SessionType.USER, access_token="at",
                                   userinfo={"iss": "https://issuer", "sub": "u1"}, realm="test")
    with session_lock(sid):
        started = time.monotonic()
        resp = web.put("/session", headers=_bearer(skey))
    assert resp.status_code == 200
    assert time.monotonic() - started < 1.0


def test_worker_reaugments_after_a_token_refresh(app, store, endpoint, due_device_session, monkeypatch):
    endpoint.release.set()
    provider = RecordingProvider(due_device_session)
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = {"test": provider}
    _one_worker_pass(app, monkeypatch)
    assert endpoint.calls == 1
    assert provider.calls == 1
    assert provider.lock_held_during_call == [False]
    assert store.get_session_data(due_device_session).userinfo["roles"] == ["tag:example.org,2026:role/Member"]


def test_worker_does_not_reaugment_without_a_token_refresh(app, store, endpoint, monkeypatch):
    endpoint.release.set()
    sid, _ = _device_session(store, token_due=False)
    provider = RecordingProvider(sid)
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = {"test": provider}
    _one_worker_pass(app, monkeypatch)
    assert endpoint.calls == 0
    assert provider.calls == 0
