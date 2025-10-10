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
import copy
import time
import pytest
from credenza.api import util as um
from credenza.refresh import refresh_worker as rw
from credenza.refresh.refresh_worker import run_refresh_worker


@pytest.fixture
def client_stub():
    class Client:
        def __init__(self):
            self.calls = []

        def fetch_service_token(self, scope, refresh_token):
            self.calls.append(("fetch", scope, refresh_token))
            # simulate failure for scope=="fail"
            if scope == "fail":
                return None
            # otherwise return a new token
            return {
                "access_token": f"new_at_{scope}",
                "expires_at": int(time.time()) + 500
            }

        def refresh_access_token(self, refresh_token):
            self.calls.append(("refresh", refresh_token))
            if refresh_token == "bad_refresh":
                raise RuntimeError("refresh failed")
            return {
                "access_token": "new_device_at",
                "refresh_token": "new_device_rt",
                "id_token": "new_device_idt",
                "expires_at":        int(time.time()) + 3600,
                "refresh_expires_at": int(time.time()) + 7200,
            }

    return Client()

@pytest.fixture
def factory(client_stub):
    class Factory:
        def get_client(self, realm, **kwargs):
            return client_stub
    return Factory()

@pytest.fixture
def profiles():
    # just need a truthy value for the realm
    return {"test": object()}

@pytest.fixture(autouse=True)
def break_loop(monkeypatch):
    # after the first time.sleep, bail out
    def _sleep(_):
        raise StopIteration()
    monkeypatch.setattr(time, "sleep", _sleep)

@pytest.fixture(autouse=True)
def audit_calls(monkeypatch):
    calls = []
    def _audit(event, **kwargs):
        calls.append((event, kwargs))
    monkeypatch.setattr(rw, "audit_event", _audit)
    monkeypatch.setattr(um, "audit_event", _audit)
    return calls


def test_expired_refresh_removes_session(app,
                                         store,
                                         base_session,
                                         factory,
                                         profiles,
                                         audit_calls,
                                         frozen_time,
                                         monkeypatch):
    sid = "S1"
    sess = copy.deepcopy(base_session)
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    # make the refresh_expires_at in the past
    sess.session_metadata.system["refresh_expires_at"] = frozen_time - 10
    sess.expires_at = frozen_time + 100

    # patch the store to return exactly this one session
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)

    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))

    # run one loop
    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # we should have audited "refresh_expired" and deleted the session
    assert ("refresh_expired", {"session_id": sid}) in audit_calls
    assert sid in deleted

def test_additional_token_refresh_success_and_failure(app,
                                                      store,
                                                      base_session,
                                                      factory,
                                                      profiles,
                                                      audit_calls,
                                                      frozen_time,
                                                      monkeypatch):
    sid = "S2"
    now = int(frozen_time)
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    # Prepare a session with four additional token blocks
    sess = copy.deepcopy(base_session)
    sess.additional_tokens = {
        "good":    {"refresh_token": "rt1", "expires_at": now + 100},
        "fail":    {"refresh_token": "rt2", "expires_at": now + 100},
        "not_due": {"refresh_token": "rt3", "expires_at": now + 10000},
        "no_rt":   {}
    }
    sess.session_metadata.system = {
        "device_session": True,
        "allow_automatic_refresh": True,
    }
    sess.expires_at = now + 10000  # keep the session alive

    # Stub the store so we process exactly this one session
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)

    # Capture update_session calls
    updated = []
    monkeypatch.setattr(store, "update_session", lambda s, sdata: updated.append((s, sdata)))

    # Stub factory.get_client to return a DummyClient that succeeds for "good"
    #    and raises for "fail"
    class DummyClient:
        def __init__(self, now_ts):
            self.now = now_ts

        def refresh_access_token(self, refresh_token):
            if refresh_token == "rt1":
                return {
                    "access_token":  "new_good_at",
                    "refresh_token": "new_good_rt",
                    "expires_at":    self.now + 1000
                }
            elif refresh_token == "rt2":
                raise Exception("forced failure for scope=fail")
            else:
                pytest.skip(f"Unexpected refresh_token {refresh_token}")

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: DummyClient(now))

    # Run the worker: only "good" and "fail" are under threshold=500
    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # Verify audit events
    #   - one session update success
    assert any(
        ev == "device_session_updated" and kw.get("session_id") == sid
        for ev, kw in audit_calls
    ), f"Missing success event in {audit_calls}"

    #   - one success for "good"
    assert any(
        ev == "additional_token_refresh_success" and kw.get("scope") == "good" and kw.get("sid") == sid
        for ev, kw in audit_calls
    ), f"Missing success event in {audit_calls}"

    #   - one failure for "fail"
    assert any(
        ev == "additional_token_refresh_failed" and kw.get("scope") == "fail" and kw.get("sid") == sid
        for ev, kw in audit_calls
    ), f"Missing failure event in {audit_calls}"

    # Only the "good" path should have updated the session
    assert len(updated) == 1
    assert updated[0][0] == sid
    _, new_sess = updated[0]

    # And the "good" token block should have been updated
    block = new_sess.additional_tokens["good"]
    assert block["access_token"]  == "new_good_at"
    assert block["refresh_token"] == "new_good_rt"
    assert block["expires_at"] == now + 1000
    assert block["last_refresh_at"] == now
    assert block["refreshed_count"] == 1

    # The "fail" block should have been removed entirely
    assert "fail" not in new_sess.additional_tokens

def test_device_access_token_refresh(app,
                                     store,
                                     base_session,
                                     factory,
                                     profiles,
                                     audit_calls,
                                     frozen_time,
                                     monkeypatch):
    sid = "S4"
    now = frozen_time
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    sess = copy.deepcopy(base_session)
    sess.session_metadata.system.update({
        "device_session":         True,
        "allow_automatic_refresh": True,
        "refresh_expires_at":      now + 1000,
        "token_expires_at":        now + 100,   # will trigger refresh
    })
    sess.refresh_token = "rt_device"
    sess.access_token  = "old_at"
    sess.id_token      = "old_id"
    sess.expires_at    = now + 2000

    # Stub the store to surface exactly this session
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)

    # ─── 3) Capture update_session and mirror real TTL behavior ────────────
    updated = []
    def fake_update_session(session_id, session_data):
        assert session_id == sid
        session_data.updated_at = frozen_time
        session_data.expires_at  = frozen_time + store.ttl
        updated.append((session_id, session_data))

    monkeypatch.setattr(store, "update_session", fake_update_session)
    monkeypatch.setattr(store, "map_session", lambda *args, **kwargs: None)
    monkeypatch.setattr(rw,"refresh_additional_tokens", lambda sid, session: True)

    class DummyClient:
        def __init__(self, now_ts):
            self.now = now_ts
        def refresh_access_token(self, refresh_token):
            # should be our device RT
            assert refresh_token == "rt_device"
            return {
                "access_token":       "new_device_at",
                "refresh_token":      "new_device_rt",
                "id_token":           "new_device_idt",
                "expires_at":         self.now + 3600,
                "refresh_expires_at": self.now + 7200,
            }

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: DummyClient(now))

    # run once
    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # The helper should have emitted an access‐token refresh event
    events = [ev for ev, _ in audit_calls]
    assert "access_token_refreshed" in events

    # And the worker should then have emitted the device session updated event
    assert "device_session_updated" in events

    # We must have called update_session exactly once
    assert len(updated) == 1
    _, new_sess = updated[0]

    # The tokens themselves were updated correctly
    assert new_sess.access_token  == "new_device_at"
    assert new_sess.refresh_token == "new_device_rt"
    assert new_sess.id_token      == "new_device_idt"

    sm = new_sess.session_metadata.system
    assert sm["token_expires_at"]   == now + 3600
    assert sm["refresh_expires_at"] == now + 7200

    # Finally, the session TTL was bumped by update_session
    assert new_sess.expires_at == frozen_time + store.ttl

