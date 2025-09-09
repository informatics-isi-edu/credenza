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
import uuid
import time
import json
import base64
from unittest.mock import Mock
from flask import g
from urllib.parse import urlparse, parse_qs
from credenza.rest import device_flow as df
from credenza.api.session.storage.session_store import SessionData
from credenza.rest.device_flow import device_callback

class StubDeviceClient:
    def __init__(self, *, tokens=None, userinfo=None, scope="openid email profile"):
        self.scope = scope
        self._tokens = tokens or {}
        self._userinfo = userinfo or {}

    def create_authorization_url(self, **kwargs):
        # must return (auth_url, auth_state, code_verifier)
        # include state/nonce in the URL so assertions can read them
        state = kwargs.get("state", "")
        nonce = kwargs.get("nonce", "")
        redirect_uri = kwargs.get("redirect_uri", "")
        access_type = kwargs.get("access_type", "")
        url = f"https://idp.example/auth?state={state}&nonce={nonce}&redirect_uri={redirect_uri}&access_type={access_type}"
        return (url, None, "stub-cv")

    def exchange_code_for_tokens(self, code, redirect_uri, code_verifier):
        return self._tokens

    def validate_id_token(self, id_token, nonce):
        return self._userinfo

@pytest.fixture
def client(app, store, monkeypatch):
    """Register the device blueprint and return a test client."""
    app.register_blueprint(df.device_blueprint)
    app.testing = True
    return app.test_client()

def test_start_device_flow_defaults(client, app, store, frozen_time):
    resp = client.post("/device/start")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "device_code" in data and uuid.UUID(data["device_code"])
    assert "user_code" in data and len(data["user_code"]) == 8
    assert data["interval"] == 3
    assert data["expires_in"] == df.DEVICE_TTL
    assert data["verification_uri"].endswith(f"/device/verify/{data['user_code']}")
    flow = store.get_device_flow(data["device_code"])
    assert flow["user_code"] == data["user_code"]
    assert flow["realm"] == app.config["DEFAULT_REALM"]
    assert flow["issued_at"] == frozen_time
    assert flow["expires_at"] == frozen_time + df.DEVICE_TTL
    assert store.get_device_code_for_usercode(data["user_code"]) == data["device_code"]

def test_start_device_flow_custom_realm(client, app, store):
    resp = client.post("/device/start?realm=test")
    assert resp.status_code == 200
    flow = store.get_device_flow(resp.get_json()["device_code"])
    assert flow["realm"] == "test"

def test_verify_device_invalid_user_code(client, app, store):
    resp = client.get("/device/verify/BADCODE")
    assert resp.status_code == 404

def test_verify_device_expired_flow(client, app, store):
    store.set_usercode_mapping("UC", "DC", ttl=10)
    resp = client.get("/device/verify/UC")
    assert resp.status_code == 404

def test_verify_device_redirect(client, app, store, monkeypatch):
    device_code = "DCODE"
    user_code = "UCODE12"
    store.set_usercode_mapping(user_code, device_code, ttl=10)
    flow = {
        "user_code": user_code,
        "verified": False,
        "issued_at": 0,
        "expires_at": 0,
        "session_key": None,
        "realm": app.config["DEFAULT_REALM"],
        "redirect_uri": f"{app.config['BASE_URL']}/device/callback",
    }
    store.set_device_flow(device_code, flow, ttl=10)

    # nonce is deterministic for assertion
    monkeypatch.setattr(df, "generate_nonce", lambda: "NONCE123")

    # stub the OIDC client returned by the factory
    stub = StubDeviceClient()
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda realm, native_client=True: stub)

    resp = client.get(f"/device/verify/{user_code}")
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    qs = parse_qs(urlparse(loc).query)
    assert qs["state"][0] == f"{device_code}"
    assert qs["nonce"][0] == "NONCE123"
    assert store.get_device_flow(qs["state"][0])["nonce"] == "NONCE123"

@pytest.mark.parametrize("qs,expected_status", [
    ({}, 400),
    ({"code": "c"}, 400),
    ({"state": "DC"}, 400),
])
def test_device_callback_bad_request(client, app, store, qs, expected_status):
    resp = client.get("/device/callback", query_string=qs)
    assert resp.status_code == expected_status

def test_device_callback_not_found_flow(client, app, store):
    resp = client.get("/device/callback", query_string={"code":"c","state":"UNKNOWN"})
    assert resp.status_code == 404

def test_device_callback_missing_nonce(client, app, store, monkeypatch):
    device_code = "D4"
    state = f"{device_code}"
    store.set_device_flow(device_code, {
        "realm": app.config["DEFAULT_REALM"],
        "redirect_uri": f"{app.config['BASE_URL']}/device/callback",
        "code_verifier": "cv123",
    }, ttl=10)

    stub = StubDeviceClient(tokens={})
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda realm, native_client=True: stub)

    resp = client.get("/device/callback", query_string={"code":"c","state":state})
    assert resp.status_code == 400


def test_device_poll_rate_limit(client, app, store, monkeypatch, frozen_time):
    """
    If a client polls for a token more frequently than the 'interval',
    we should return a 429 slow_down error.
    """
    device_code = "RATE1"

    # Set up a fresh device flow with last_poll_at == frozen_time
    flow = {
        "realm": app.config["DEFAULT_REALM"],
        "verified": False,
        "last_poll_at": frozen_time,
        "interval": app.config.get("DEVICE_POLL_INTERVAL", 3),
    }
    store.set_device_flow(device_code, flow, ttl=20)

    # First poll (at frozen_time) should be too fast -> 429
    resp1 = client.post("/device/token", json={"device_code": device_code})
    assert resp1.status_code == 429
    data1 = resp1.get_json()
    assert data1["error"] == "too_many_requests"
    assert data1["message"] == "slow_down"
    assert data1["code"] == 429

    # Advance time to exactly interval seconds later
    interval = app.config.get("DEVICE_POLL_INTERVAL", 3)
    monkeypatch.setattr(time, "time", lambda: frozen_time + interval)

    # Second poll at frozen_time + interval should now proceed
    # Since still unverified, it returns authorization_pending (403)
    resp2 = client.post("/device/token", json={"device_code": device_code})
    assert resp2.status_code == 403
    data2 = resp2.get_json()
    assert data2["error"] == "authorization_pending"

def test_device_callback_success(client, app, store, monkeypatch, frozen_time):
    device_code = "D5"
    state = f"{device_code}"
    flow = {
        "realm": app.config["DEFAULT_REALM"],
        "redirect_uri": f"{app.config['BASE_URL']}/device/callback",
        "nonce": "N123",
        "code_verifier": "VERIFIER123",
        "refresh": False,
    }
    store.set_device_flow(device_code, flow, ttl=10)

    tokens = {
        "id_token":"idtok","access_token":"acc","refresh_token":"rt",
        "scope":"openid","refresh_expires_in":0,"expires_at":frozen_time+300
    }
    userinfo = {"sub":"u","email":"e"}

    stub = StubDeviceClient(tokens=tokens, userinfo=userinfo, scope="openid")
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda realm, native_client=True: stub)

    provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("default")
    monkeypatch.setattr(provider, "process_additional_tokens", lambda t, now: {})
    monkeypatch.setattr(provider, "enrich_userinfo", lambda ui, ext: None)

    resp = client.get("/device/callback", query_string={"code":"c","state":state})
    assert resp.status_code == 200
    assert b"Device authorization complete" in resp.data

    new_flow = store.get_device_flow(device_code)
    assert new_flow["verified"] is True
    skey = new_flow["session_key"]
    sid, session = store.get_session_by_session_key(skey)
    assert isinstance(session, SessionData)
    assert session.access_token == "acc"

def test_poll_for_token_missing_device_code(client, app):
    resp = client.post("/device/token", json={})
    assert resp.status_code == 400

def test_poll_for_token_expired_flow(client, app, store):
    resp = client.post("/device/token", json={"device_code":"X"})
    assert resp.status_code == 400

def test_poll_for_token_pending(client, app, store, frozen_time):
    store.set_device_flow("P1", {"verified":False, "session_key":None}, ttl=10)
    resp = client.post("/device/token", json={"device_code":"P1"})
    assert resp.status_code == 403
    assert resp.get_json() == {"error":"authorization_pending"}

def test_poll_for_token_success(client, app, store, frozen_time):
    sid = "S10"
    skey, session = store.create_session(
        session_id=sid,
        access_token="acc",
        userinfo={"sub":"u"},
        realm=app.config["DEFAULT_REALM"],
        id_token="idtok",
        refresh_token="rt",
        scopes="openid"
    )
    store.set_device_flow("R1", {"verified":True, "session_key":skey}, ttl=10)
    resp = client.post("/device/token", json={"device_code":"R1"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["access_token"] == skey
    assert data["token_type"] == "Bearer"
    assert abs(data["expires_in"] - store.get_ttl("S10")) < 1

def test_device_logout_not_device(client, app, store, monkeypatch):
    sid = "S20"
    skey, session = store.create_session(
        session_id=sid,
        access_token="acc",
        userinfo={"sub":"u","email":"e"},
        realm=app.config["DEFAULT_REALM"],
        id_token="idtok",
        refresh_token="rt",
        scopes="openid"
    )
    monkeypatch.setattr(df, "get_current_session", lambda: (skey, session))
    resp = client.post("/device/logout")
    assert resp.status_code == 403

def test_device_logout_success(client, app, store, monkeypatch):
    sid = "S21"
    skey, session = store.create_session(
        session_id=sid,
        access_token="acc",
        userinfo={"sub":"u","email":"e"},
        realm=app.config["DEFAULT_REALM"],
        id_token="idtok",
        refresh_token="rt",
        scopes="openid",
        metadata={"device_session":True}
    )
    monkeypatch.setattr(df, "get_current_session", lambda: (sid, session))

    # Stub the OIDC client factory to avoid any network
    calls = []
    class DummyClient:
        def revoke_token(self, scope, token, token_type_hint=None):
            calls.append((scope, token_type_hint))
            return True

    monkeypatch.setattr(
        app.config["OIDC_CLIENT_FACTORY"],
        "get_client",
        lambda realm, **kwargs: DummyClient(),   # accept native_client kwarg
    )

    resp = client.post("/device/logout")
    assert resp.status_code == 200
    assert resp.get_json() == {"status":"logged out"}
    assert store.get_session_data(sid) is None

    # prove we invoked revocation
    assert any(t == "access_token" for _, t in calls) or calls  # depending on your route logic


def test_device_callback_deferred_augmentation(app, base_session, monkeypatch):
    store = app.config["SESSION_STORE"]
    device_code = "test-device-code"
    session_key = "deferred-device-session-key"
    session_id = "deferred-device-session-id"

    dummy_tokens = {"id_token": "id", "access_token": "atk", "scope": "openid email"}
    dummy_userinfo = {"sub": "123", "email": "u@example.com"}
    dummy_augmented_userinfo = {"sub": "123", "email": "u@example.com", "groups": ["g1"]}
    dummy_additional_tokens = {"foo": "bar"}

    store.set_device_flow(device_code, {
        "user_code": "abcd1234",
        "verified": False,
        "issued_at": time.time(),
        "expires_at": time.time() + 600,
        "session_key": None,
        "realm": "test",
        "refresh": False,
        "nonce": "abc123",
        "code_verifier": "def345",
        "redirect_uri": f"{app.config['BASE_URL']}/device/callback",
    }, 600)

    # Stub client via factory
    stub = StubDeviceClient(tokens=dummy_tokens, userinfo=dummy_userinfo, scope="openid email")
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda realm, native_client=True: stub)

    # Session helpers
    monkeypatch.setattr(store, "generate_session_id", lambda: session_id)
    monkeypatch.setattr(store, "create_session", lambda **kwargs: (session_key, base_session))

    # Augmentation: first call defers, second returns augmented result
    call_count = {"count": 0}
    def mock_augment(tokens, realm, userinfo, metadata):
        call_count["count"] += 1
        if call_count["count"] == 1:
            metadata["augmentation_deferred"] = True
            return userinfo, {}
        else:
            return dummy_augmented_userinfo, dummy_additional_tokens
    monkeypatch.setattr("credenza.rest.device_flow.augment_session", mock_augment)

    update_mock = Mock()
    monkeypatch.setattr(store, "update_session", update_mock)

    with app.test_request_context(f"/device/callback?code=abc&state={device_code}"):
        g.session_key = session_key
        resp = device_callback()

    assert resp == "Device authorization complete. You may return to the device."
    assert call_count["count"] == 2
    update_mock.assert_called_once()
    updated_sid, updated_session = update_mock.call_args[0]
    assert updated_sid == session_id
    assert updated_session.userinfo == dummy_augmented_userinfo
    assert updated_session.additional_tokens == dummy_additional_tokens


