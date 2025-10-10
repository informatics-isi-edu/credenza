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
import copy
import pytest
from datetime import datetime
from werkzeug.exceptions import NotFound
from credenza.rest import session as sm
from credenza.api import util as um
from credenza.rest.session import session_blueprint
from credenza.api.util import get_effective_scopes


@pytest.fixture
def app(app, fake_current_session, monkeypatch):
    app.register_blueprint(session_blueprint)

    return app

@pytest.fixture
def client(app):
    app.testing = True
    return app.test_client()

@pytest.fixture(autouse=True)
def audit_calls(monkeypatch):
    calls = []
    def _audit(event, **kwargs):
        calls.append((event, kwargs))
    monkeypatch.setattr(sm, "audit_event", _audit)
    monkeypatch.setattr(um, "audit_event", _audit)
    return calls

def test_whoami(client):
    resp = client.get("/whoami")
    assert resp.status_code == 200

    # Should echo the session.userinfo dict
    assert resp.json["sub"] == "user1"
    assert resp.json["email"] == "user1@example.com"

def test_whoami_unauthenticated(monkeypatch, client):
    monkeypatch.setattr(sm,"get_current_session", lambda: (_ for _ in ()).throw(NotFound()))
    resp = client.get("/whoami")
    assert resp.status_code == 404

def test_get_session(client):
    resp = client.get("/session")
    assert resp.status_code == 200
    data = resp.json

    # Check some fields in non-legacy mode
    assert data["sub"] == "user1"
    assert data["id"] == "https://issuer/user1"
    assert data["email"] == "user1@example.com"
    assert data["scopes"] == ["openid", "email", "profile"]
    assert isinstance(data["created_at"], str)
    assert "seconds_remaining" in data

def test_get_session_unauthenticated(monkeypatch, client):
    monkeypatch.setattr(sm,"get_current_session", lambda: (_ for _ in ()).throw(NotFound()))
    resp = client.get("/session")
    assert resp.status_code == 404

def test_get_session_invalid_bearer(monkeypatch, client):
    monkeypatch.setattr(sm,"get_current_session", lambda: (_ for _ in ()).throw(NotFound()))
    resp = client.get("/session", headers={"Authorization": "Bearer invalid.token"})
    assert resp.status_code == 404

def test_put_session_extend(client, store, frozen_time):
    # Capture original values before the PUT
    before = store.get_session_data("fake_current_sid")
    old_expires_at = before.expires_at

    resp = client.put("/session")
    assert resp.status_code == 200

    after = store.get_session_data("fake_current_sid")

    # update_session sets updated_at to time.time() (frozen_time in tests)
    assert after.updated_at == pytest.approx(frozen_time, abs=1)

    # update_session sets expires_at = max(current_expires_at, now + ttl)
    expected_expires = max(old_expires_at, frozen_time + store.ttl)
    assert after.expires_at == pytest.approx(expected_expires, abs=1)


def test_put_session_expired(client, app, monkeypatch):
    sid, sess = sm.get_current_session()
    sess.session_metadata.system["refresh_expires_at"] = int(time.time()) + 60
    monkeypatch.setattr(sm, "revoke_tokens", lambda sid, session: None)
    with app.app_context():
        app.config["SESSION_EXPIRY_THRESHOLD"] = 300
    resp = client.put("/session")
    assert resp.status_code == 401

def test_put_session_with_refresh_access_token(client,
                                               app,
                                               store,
                                               base_session,
                                               frozen_time,
                                               monkeypatch,
                                               audit_calls):
    sid = "S1"
    now = frozen_time

    # Make a deep‐copy so we don't clobber other tests
    sess = copy.deepcopy(base_session)
    # Simulate an expired access token, but a still‐valid refresh token
    sess.session_metadata.system.update({
        "token_expires_at":   now - 1,    # already expired
        "refresh_expires_at": now + 600,  # still valid
    })
    sess.refresh_token = "old_refresh_token"
    sess.access_token  = "old_access_token"
    sess.id_token      = "old_id_token"

    # Record current expires_at so we can assert the max() behavior
    original_expires_at = sess.expires_at

    # Stub get_current_session -> (sid, sess)
    monkeypatch.setattr(sm,"get_current_session", lambda: (sid, sess))

    # Stub out map_session
    monkeypatch.setattr(store, "map_session", lambda session_key, session_id, ttl: "dummy-map-key")

    # Configure our dummy OIDC client factory in Flask config
    class DummyClient:
        def __init__(self, now_ts):
            self.now = now_ts
        def refresh_access_token(self, refresh_token):
            # ensure the right RT is passed in
            assert refresh_token == "old_refresh_token"
            return {
                "access_token":       "new_access_token",
                "refresh_token":      "new_refresh_token",
                "id_token":           "new_id_token",
                "expires_at":         self.now + 3600,
                "refresh_expires_at": self.now + 7200,
            }

    class DummyFactory:
        def get_client(self, realm, native_client=False):
            assert realm == sess.realm
            return DummyClient(now)

    with app.app_context():
        app.config["TOKEN_EXPIRY_THRESHOLD"] = 300
        # Inject our dummy factory
        app.config["OIDC_CLIENT_FACTORY"] = DummyFactory()

    resp = client.put("/session?refresh_upstream=true")
    assert resp.status_code == 200

    # Audit events
    assert any(ev == "access_token_refreshed" for ev, _ in audit_calls), audit_calls
    assert any(ev == "session_updated" for ev, _ in audit_calls), audit_calls

    # Fetch the persisted session from the store
    updated = store.get_session_data(sid)

    # Check that the real refresh_access_token ran:
    assert updated.access_token  == "new_access_token"
    assert updated.refresh_token == "new_refresh_token"
    assert updated.id_token      == "new_id_token"

    # Check that the helper wrote back the new expiry metadata
    meta = updated.session_metadata.system
    assert meta["token_expires_at"]   == now + 3600
    assert meta["refresh_expires_at"] == now + 7200

    # update_session should have bumped updated_at and applied max() for expires_at
    assert updated.updated_at == pytest.approx(now, abs=1)
    expected_expires = max(original_expires_at, now + store.ttl)
    assert updated.expires_at == pytest.approx(expected_expires, abs=1)


def test_put_session_with_refresh_access_token_failure(client,
                                                       app,
                                                       store,
                                                       base_session,
                                                       frozen_time,
                                                       monkeypatch,
                                                       audit_calls):
    sid = "S_fail"
    now = frozen_time

    # Copy session and simulate token about to expire, but refresh still valid
    sess = copy.deepcopy(base_session)
    sess.session_metadata.system.update({
        "token_expires_at":   now - 1,    # already expired
        "refresh_expires_at": now + 600,  # still valid
    })
    sess.refresh_token = "bad_refresh_token"
    sess.access_token  = "old_access_token"
    sess.id_token      = "old_id_token"

    original_expires_at = sess.expires_at

    # Patch get_current_session
    monkeypatch.setattr(sm, "get_current_session", lambda: (sid, sess))

    # Patch map_session
    monkeypatch.setattr(store, "map_session", lambda session_key, session_id, ttl: "dummy-map-key")

    # Configure dummy client that fails
    class DummyFailClient:
        def refresh_access_token(self, refresh_token):
            assert refresh_token == "bad_refresh_token"
            raise Exception("mock token refresh failure")

    class DummyFactory:
        def get_client(self, realm, native_client=False):
            assert realm == sess.realm
            return DummyFailClient()

    with app.app_context():
        app.config["TOKEN_EXPIRY_THRESHOLD"] = 300
        app.config["OIDC_CLIENT_FACTORY"] = DummyFactory()

    resp = client.put("/session?refresh_upstream=true")
    assert resp.status_code == 200

    # Check audit includes the failure
    assert any(ev == "access_token_refresh_failed" for ev, _ in audit_calls), audit_calls
    assert any(ev == "session_updated" for ev, _ in audit_calls), audit_calls

    # Fetch stored session
    updated = store.get_session_data(sid)

    # Verify no token fields were changed
    assert updated.access_token  == "old_access_token"
    assert updated.refresh_token == "bad_refresh_token"
    assert updated.id_token      == "old_id_token"

    # Metadata should be unchanged
    meta = updated.session_metadata.system
    assert meta["token_expires_at"]   == now - 1
    assert meta["refresh_expires_at"] == now + 600

    # update_session should have bumped updated_at and applied max() for expires_at
    assert updated.updated_at == pytest.approx(now, abs=1)
    expected_expires = max(original_expires_at, now + store.ttl)
    assert updated.expires_at == pytest.approx(expected_expires, abs=1)


def test_put_session_additional_tokens_refresh(client,
                                               app,
                                               store,
                                               base_session,
                                               frozen_time,
                                               monkeypatch,
                                               audit_calls):
    sid = "S2"
    now = frozen_time
    threshold = 500

    # Prepare a session with four additional token blocks:
    sess = copy.deepcopy(base_session)
    sess.additional_tokens = {
        "good":    {"refresh_token": "rt_good", "expires_at": now - threshold - 1},
        "fail":    {"refresh_token": "rt_fail", "expires_at": now - threshold - 1},
        "not_due": {"refresh_token": "rt_nd",   "expires_at": now + 10000},
        "no_rt":   {}
    }
    sess.session_metadata.system = {}
    sess.refresh_token = None   # primary flow not under test here
    sess.expires_at = now + 10000

    # Stub get_current_session so GET/PUT /session uses our SID and session
    monkeypatch.setattr(sm, "get_current_session", lambda: (sid, sess))

    monkeypatch.setattr(store, "map_session", lambda session_key, session_id, ttl: "dummy-map-key")

    # Capture calls to update_session, and make it return (session_key, session_data)
    updated_calls = []
    def _update_session(s, sd):
        updated_calls.append((s, sd))
        return ("dummy-map-key", sd)
    monkeypatch.setattr(store, "update_session", _update_session)

    # Provide a DummyClient that succeeds for "rt_good" and raises for "rt_fail"
    class DummyClient:
        def __init__(self, now_ts):
            self.now = now_ts
        def refresh_access_token(self, refresh_token):
            if refresh_token == "rt_good":
                return {
                    "access_token":  "new_good_at",
                    "refresh_token": "new_good_rt",
                    "expires_at":    self.now + 2000,
                }
            elif refresh_token == "rt_fail":
                raise RuntimeError("forced failure for rt_fail")
            else:
                pytest.skip(f"Unexpected refresh_token: {refresh_token}")

    class DummyFactory:
        def get_client(self, realm, native_client=False):
            assert realm == sess.realm
            return DummyClient(now)

    with app.app_context():
        app.config["TOKEN_EXPIRY_THRESHOLD"] = 300
        app.config["OIDC_CLIENT_FACTORY"] = DummyFactory()

    # Perform the PUT /session
    resp = client.put("/session?refresh_upstream=true")
    assert resp.status_code == 200

    # Check that we emitted both the success and failure audit events
    events = [ev for ev, _ in audit_calls]
    assert "additional_token_refresh_success" in events, audit_calls
    assert "additional_token_refresh_failed"  in events, audit_calls

    # Only the "good" path should have resulted in update_session
    assert len(updated_calls) == 1
    called_sid, new_sess = updated_calls[0]
    assert called_sid == sid

    # Verify the "good" block was updated correctly
    good = new_sess.additional_tokens["good"]
    assert good["access_token"]    == "new_good_at"
    assert good["refresh_token"]   == "new_good_rt"
    assert good["expires_at"]      == now + 2000
    assert good["refreshed_count"] == 1

    # The "fail" block should have been removed
    assert "fail" not in new_sess.additional_tokens

    # The "not_due" and "no_rt" blocks remain untouched
    assert "not_due" in new_sess.additional_tokens
    assert "no_rt"   in new_sess.additional_tokens

def test_patch_session_success(client, app, store):
    patch_data = {"foo": "bar"}
    resp = client.patch("/session", json=patch_data)
    assert resp.status_code == 200
    assert resp.json == {"status": "updated", "patched": patch_data}

    session = store.get_session_data("fake_current_sid")
    # The 'user' section of session_metadata should contain our patch
    assert session.session_metadata.user == patch_data

def test_patch_session_invalid_json(client):
    resp = client.patch("/session", data="not json", content_type="application/json")
    assert resp.status_code == 400

def test_delete_session_legacy(client, app, monkeypatch):
    monkeypatch.setattr(sm,"revoke_tokens", lambda sid, session: None)
    app.config["ENABLE_LEGACY_API"] = True
    resp = client.delete("/session")
    assert resp.status_code == 303
    assert resp.headers["Location"] == "https://localhost/logout"

def test_delete_session_normal(client, app, monkeypatch):
    monkeypatch.setattr(sm,"revoke_tokens", lambda sid, session: None)
    resp = client.delete("/session")
    assert resp.status_code == 200
    assert resp.json == {"status": "logged out"}
    # Cookie should be cleared
    cookie = resp.headers.get("Set-Cookie", "")
    assert app.config["COOKIE_NAME"] in cookie and "Expires=Thu, 01 Jan 1970" in cookie

def test_make_session_response_non_legacy(app, store, base_session):
    # Arrange deterministic timestamps
    base_session.created_at = 1000000
    base_session.updated_at = 1000500
    base_session.expires_at = 1001000

    app.config["ENABLE_LEGACY_API"] = False

    with app.app_context():
        resp = sm.make_session_response("sid123", base_session)

    # Core user fields
    assert resp["preferred_username"] == base_session.userinfo["preferred_username"]
    assert resp["full_name"] == base_session.userinfo["name"]
    assert resp["email"] == base_session.userinfo["email"]
    assert resp["email_verified"] is True
    assert resp["id"] == base_session.userinfo["id"]
    assert resp["sub"] == base_session.userinfo["sub"]
    assert resp["iss"] == base_session.userinfo["iss"]
    assert resp["aud"] == base_session.userinfo["aud"]
    assert resp["groups"] == base_session.userinfo["groups"]
    assert resp["roles"] == base_session.userinfo["roles"]

    # Scopes and metadata
    assert resp["scopes"] == get_effective_scopes(base_session)
    assert resp["metadata"] == base_session.session_metadata.to_dict()

    # Parse ISO strings and compare timestamps
    for field in ("created_at", "updated_at", "expires_at"):
        iso = resp[field]
        dt = datetime.fromisoformat(iso)
        # allow 1 second drift
        assert abs(dt.timestamp() - getattr(base_session, field)) < 1

    assert resp["seconds_remaining"] == store.get_ttl("sid123")

@pytest.mark.usefixtures("app", "store", "base_session")
def test_make_session_response_legacy(app, store, base_session):
    # Arrange deterministic timestamps
    base_session.created_at = 1000000
    base_session.updated_at = 1000500
    base_session.expires_at = 1001000

    app.config["ENABLE_LEGACY_API"] = True

    with app.app_context():
        resp = sm.make_session_response("sid123", base_session)

    client_info = resp["client"]
    issuer = base_session.userinfo["iss"]
    sub = base_session.userinfo["sub"]

    # Legacy 'client' object
    assert client_info["id"] == f"{issuer}/{sub}"
    assert client_info["display_name"] == base_session.userinfo["preferred_username"]
    assert client_info["full_name"] == base_session.userinfo["name"]
    assert client_info["email"] == base_session.userinfo["email"]

    # Identities from identity_set
    expected_idents = [f"{issuer}/{ident['sub']}" for ident in base_session.userinfo["identity_set"]]
    assert resp["client"]["identities"] == expected_idents

    # 'attributes' array contains client then groups
    attrs = resp["attributes"]
    assert attrs[0] == client_info
    # First group (string) converted to dict
    assert {"id": "g1", "display_name": "g1"} in attrs
    # Second group (dict) preserved
    assert base_session.userinfo["groups"][1] in attrs

    # Legacy lifecycle fields: parse and compare
    since_dt = datetime.fromisoformat(resp["since"])
    expires_dt = datetime.fromisoformat(resp["expires"])
    assert abs(since_dt.timestamp() - base_session.created_at) < 1
    assert abs(expires_dt.timestamp() - base_session.expires_at) < 1

    assert resp["seconds_remaining"] == store.get_ttl("sid123")
