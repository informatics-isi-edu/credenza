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
import json
import time
import logging
import pytest
from credenza.api.common import util as um
from credenza.refresh import refresh_worker as rw
from credenza.api.session.storage import session_store as ss
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
    monkeypatch.setattr(ss, "audit_event", _audit)
    return calls


def test_absolute_expiry_removes_session(app,
                                         store,
                                         device_session,
                                         factory,
                                         profiles,
                                         audit_calls,
                                         frozen_time,
                                         monkeypatch):
    sid = "S1"
    sess = copy.deepcopy(device_session)
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    # absolute_expires_at is in the past; no allow_automatic_refresh so no refresh is attempted
    sess.absolute_expires_at = frozen_time - 10
    sess.expires_at = frozen_time + 100
    # patch module time used by store implementation
    monkeypatch.setattr(time, "time", lambda: frozen_time)

    # patch the store to return exactly this one session
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)

    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))

    # run one loop
    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # enforce_absolute_cap should have audited and deleted the session
    logging.debug(audit_calls)
    assert ("session_deleted_absolute_lifetime_expired",
            {"session_id": sid,
             "realm": sess.realm,
             "sub": sess.userinfo.get("sub"),
             "absolute_expires_at": sess.absolute_expires_at}) in audit_calls
    assert sid in deleted


def test_refresh_extends_absolute_cap_prevents_deletion(app,
                                                        store,
                                                        device_session,
                                                        factory,
                                                        profiles,
                                                        audit_calls,
                                                        frozen_time,
                                                        monkeypatch):
    """Regression: when a device session's absolute_expires_at has just expired but
    the refresh succeeds and the IDP returns refresh_expires_in, the updated cap
    must be checked -- not the stale one -- so the session survives."""
    sid = "S_CAP"
    now = frozen_time
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    sess = copy.deepcopy(device_session)
    sess.refresh_token = "rt_cap"
    sess.session_metadata.system.update({
        "allow_automatic_refresh": True,
        "access_token_expires_at": now + 100,  # within threshold, triggers refresh
    })
    # absolute cap already expired -- this is the scenario that caused the regression
    sess.absolute_expires_at = now - 5
    sess.expires_at = now + 2000

    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)

    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))
    updated = []
    monkeypatch.setattr(store, "update_session", lambda s, sd: updated.append((s, sd)))

    class CapExtendingClient:
        def refresh_access_token(self, refresh_token):
            return {
                "access_token":       "new_cap_at",
                "refresh_token":      "new_cap_rt",
                "expires_at":         now + 3600,
                "refresh_expires_in": 7200,  # IDP extends the cap
            }

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: CapExtendingClient())
    monkeypatch.setattr(rw, "refresh_additional_tokens", lambda sid, session: False)

    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # refresh extended absolute_expires_at to now+7200, so enforce_absolute_cap
    # must NOT delete the session
    assert sid not in deleted, "session was deleted despite successful cap extension"
    assert len(updated) == 1, "session should have been updated after successful refresh"
    _, new_sess = updated[0]
    assert new_sess.absolute_expires_at == now + 7200


def test_additional_token_refresh_success_and_failure(app,
                                                      store,
                                                      device_session,
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
    sess = copy.deepcopy(device_session)
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
                                     device_session,
                                     factory,
                                     profiles,
                                     audit_calls,
                                     frozen_time,
                                     monkeypatch):
    sid = "S4"
    now = frozen_time
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    sess = copy.deepcopy(device_session)
    sess.session_metadata.system.update({
        "device_session":           True,
        "allow_automatic_refresh":  True,
        "refresh_token_expires_at": now + 1000,
        "access_token_expires_at":  now + 100,   # will trigger refresh
    })
    sess.refresh_token = "rt_device"
    sess.access_token  = "old_at"
    sess.id_token      = "old_id"
    sess.expires_at    = now + 2000

    # Stub the store to surface exactly this session
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)

    # 3) Capture update_session and mirror real TTL behavior
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
                "refresh_expires_in": 7200,
            }

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: DummyClient(now))

    # run once
    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # The helper should have emitted an access-token refresh event
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
    assert sm["access_token_expires_at"]    == now + 3600
    assert sm["refresh_token_expires_at"]   == now + 7200
    assert new_sess.absolute_expires_at     == now + 7200

    # Finally, the session TTL was bumped by update_session
    assert new_sess.expires_at == frozen_time + store.ttl


def test_refresh_preserves_absolute_cap_when_refresh_expires_in_is_zero(
        app,
        store,
        device_session,
        factory,
        profiles,
        audit_calls,
        frozen_time,
        monkeypatch):
    """Regression: Keycloak offline tokens return refresh_expires_in=0 meaning 'no expiry'.
    absolute_expires_at must NOT be set to now+0 (triggering immediate deletion)."""
    sid = "S_ZERO"
    now = frozen_time
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    sess = copy.deepcopy(device_session)
    original_cap = now + 14 * 86400
    sess.absolute_expires_at = original_cap
    sess.refresh_token = "rt_offline"
    sess.session_metadata.system.update({
        "allow_automatic_refresh": True,
        "access_token_expires_at": now + 100,  # within threshold, triggers refresh
    })
    sess.expires_at = original_cap

    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)

    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))
    updated = []
    monkeypatch.setattr(store, "update_session", lambda s, sd: updated.append((s, sd)))

    class OfflineClient:
        def refresh_access_token(self, refresh_token):
            return {
                "access_token":      "new_offline_at",
                "refresh_token":     "new_offline_rt",
                "expires_at":        now + 1500,
                "refresh_expires_in": 0,   # Keycloak offline token: "never expires"
            }

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: OfflineClient())
    monkeypatch.setattr(rw, "refresh_additional_tokens", lambda sid, session: False)

    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    assert sid not in deleted, "session deleted because refresh_expires_in=0 was treated as now+0"
    assert len(updated) == 1
    _, new_sess = updated[0]
    assert new_sess.access_token == "new_offline_at"
    assert new_sess.absolute_expires_at == original_cap, (
        f"absolute_expires_at was clobbered to {new_sess.absolute_expires_at}, expected {original_cap}"
    )


class _OAuthLikeError(Exception):
    """Mimics authlib's OAuthError, which carries an `.error` code attribute."""
    def __init__(self, error_code):
        self.error = error_code
        super().__init__(f"{error_code}: simulated")


def _refreshing_session(device_session, now):
    sess = copy.deepcopy(device_session)
    sess.refresh_token = "rt_x"
    sess.session_metadata.system.update({
        "allow_automatic_refresh": True,
        "access_token_expires_at": now + 100,  # within threshold -> triggers refresh
    })
    sess.absolute_expires_at = now + 100000
    sess.expires_at = now + 100000
    return sess


def test_terminal_refresh_error_evicts_immediately(app, store, device_session, factory,
                                                   profiles, audit_calls, frozen_time, monkeypatch):
    sid = "S_TERM"
    now = frozen_time
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    sess = _refreshing_session(device_session, now)
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)
    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))
    updated = []
    monkeypatch.setattr(store, "update_session", lambda s, sd: updated.append((s, sd)))

    class TerminalClient:
        def refresh_access_token(self, refresh_token):
            raise _OAuthLikeError("invalid_grant")

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: TerminalClient())
    monkeypatch.setattr(rw, "refresh_additional_tokens", lambda sid, session: False)

    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # invalid_grant is terminal -> evicted on the first failure, not persisted.
    assert sid in deleted
    assert not updated
    assert any(ev == "session_evicted_refresh_failures"
               and kw.get("terminal") is True and kw.get("failure_count") == 1
               for ev, kw in audit_calls), audit_calls


def test_consecutive_failures_evict_at_threshold(app, store, device_session, factory,
                                                 profiles, audit_calls, frozen_time, monkeypatch):
    sid = "S_FLAKY"
    now = frozen_time
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles
    app.config["MAX_REFRESH_FAILURES"] = 1  # evict after a single non-terminal failure

    sess = _refreshing_session(device_session, now)
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)
    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))
    monkeypatch.setattr(store, "update_session", lambda s, sd: None)

    class FlakyClient:
        def refresh_access_token(self, refresh_token):
            raise RuntimeError("network blip")  # no .error attr -> non-terminal

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: FlakyClient())
    monkeypatch.setattr(rw, "refresh_additional_tokens", lambda sid, session: False)

    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    assert sid in deleted
    assert any(ev == "session_evicted_refresh_failures"
               and kw.get("terminal") is False and kw.get("failure_count") == 1
               for ev, kw in audit_calls), audit_calls


def test_failure_below_threshold_persists_counter(app, store, device_session, factory,
                                                  profiles, audit_calls, frozen_time, monkeypatch):
    sid = "S_BELOW"
    now = frozen_time
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles
    app.config["MAX_REFRESH_FAILURES"] = 3

    sess = _refreshing_session(device_session, now)
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)
    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))
    updated = []
    monkeypatch.setattr(store, "update_session", lambda s, sd: updated.append((s, sd)))

    class FlakyClient:
        def refresh_access_token(self, refresh_token):
            raise RuntimeError("network blip")

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: FlakyClient())
    monkeypatch.setattr(rw, "refresh_additional_tokens", lambda sid, session: False)

    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # One failure, threshold not reached: not evicted, but counter persisted.
    assert sid not in deleted
    assert len(updated) == 1
    _, new_sess = updated[0]
    assert new_sess.session_metadata.system["refresh_failure_count"] == 1
    assert new_sess.session_metadata.system["last_refresh_error_terminal"] is False
    # A failure-only pass is not a "session updated" event.
    assert not any(ev == "device_session_updated" for ev, _ in audit_calls)


def test_successful_refresh_clears_failure_counter(app, store, device_session, factory,
                                                   profiles, audit_calls, frozen_time, monkeypatch):
    sid = "S_RESET"
    now = frozen_time
    app.config["OIDC_CLIENT_FACTORY"] = factory
    app.config["OIDC_IDP_PROFILES"] = profiles

    sess = _refreshing_session(device_session, now)
    sess.session_metadata.system.update({
        "refresh_failure_count": 2,
        "last_refresh_error": "network blip",
        "last_refresh_error_terminal": False,
    })
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid])
    monkeypatch.setattr(store, "get_session_data", lambda s: sess)
    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))
    updated = []
    monkeypatch.setattr(store, "update_session", lambda s, sd: updated.append((s, sd)))

    class GoodClient:
        def refresh_access_token(self, refresh_token):
            return {"access_token": "a", "refresh_token": "b", "expires_at": now + 3600}

    monkeypatch.setattr(factory, "get_client", lambda realm, **kwargs: GoodClient())
    monkeypatch.setattr(rw, "refresh_additional_tokens", lambda sid, session: False)

    with app.app_context():
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    assert sid not in deleted
    assert len(updated) == 1
    _, new_sess = updated[0]
    assert new_sess.session_metadata.system.get("refresh_failure_count", 0) == 0
    assert "last_refresh_error" not in new_sess.session_metadata.system


def test_worker_survives_pass_exception(app,
                                        store,
                                        profiles,
                                        frozen_time,
                                        monkeypatch,
                                        caplog):
    """
    With only a pass-level try/except, an exception raised for one session
    aborts the current pass but must NOT kill the worker thread. We verify
    the exception is logged and the loop reaches the sleep (triggering
    StopIteration via the break_loop fixture).
    """
    app.config["OIDC_IDP_PROFILES"] = profiles

    sid_bad = "BAD"

    # Present a single 'bad' session which will raise on get_session_data
    monkeypatch.setattr(store, "list_session_ids", lambda: [sid_bad])
    monkeypatch.setattr(store, "get_session_data", lambda _sid: (_ for _ in ()).throw(RuntimeError("boom")))

    # Keep other store methods inert if somehow called
    monkeypatch.setattr(store, "update_session", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(store, "delete_session", lambda *a, **k: None, raising=False)

    with app.app_context(), caplog.at_level(logging.ERROR):
        # The worker should catch the exception at pass level and continue to the sleep,
        # where the break_loop fixture raises StopIteration to end the test quickly.
        with pytest.raises(StopIteration):
            run_refresh_worker(app)

    # Ensure our pass-level handler logged the unhandled exception
    assert any("Unhandled exception in refresh pass" in rec.getMessage() for rec in caplog.records), \
        "Expected pass-level exception log not found"
