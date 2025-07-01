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
from urllib.parse import urlparse, parse_qs
from credenza.rest import device_flow as df
from credenza.api.session.storage.session_store import SessionData

class DummyDeviceOAuth:
    def create_authorization_url(self, url, state, nonce, redirect_uri, access_type):
        return (f"{url}?state={state}&nonce={nonce}&redirect_uri={redirect_uri},access_type={access_type}", None)

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
        "realm": app.config["DEFAULT_REALM"]
    }
    store.set_device_flow(device_code, flow, ttl=10)
    monkeypatch.setattr(df, "generate_nonce", lambda: "NONCE123")
    resp = client.get(f"/device/verify/{user_code}")
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    qs = parse_qs(urlparse(loc).query)
    assert qs["state"][0] == f"{device_code}"
    assert qs["nonce"][0] == "NONCE123"
    assert store.get_nonce(qs["state"][0]) == "NONCE123"

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
    store.set_device_flow(device_code, {"realm": app.config["DEFAULT_REALM"]}, ttl=10)
    client_obj = app.config["OIDC_CLIENT_FACTORY"].get_client(app.config["DEFAULT_REALM"])
    monkeypatch.setattr(client_obj, "exchange_code_for_tokens", lambda code, s, v: dict())
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
    store.set_device_flow(device_code, {"realm": app.config["DEFAULT_REALM"]}, ttl=10)
    store.store_nonce(state, "N123")
    # since PKCE is on by default, we must supply a verifier
    store.store_pkce_verifier(state, "VERIFIER123")

    tokens = {
        "id_token":"idtok","access_token":"acc","refresh_token":"rt",
        "scope":"openid","refresh_expires_in":0,"expires_at":frozen_time+300
    }
    client_obj = app.config["OIDC_CLIENT_FACTORY"].get_client(app.config["DEFAULT_REALM"], native_client=True)
    monkeypatch.setattr(client_obj, "exchange_code_for_tokens", lambda code, s, v: tokens)
    monkeypatch.setattr(client_obj, "validate_id_token", lambda idt, nn: {"sub":"u","email":"e"})
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
    oidc_client = app.config["OIDC_CLIENT_FACTORY"].get_client(session.realm)
    monkeypatch.setattr(oidc_client,"revoke_token",lambda token, token_type_hint="access_token": True)

    resp = client.post("/device/logout")
    assert resp.status_code == 200
    assert resp.get_json() == {"status":"logged out"}
    assert store.get_session_data(sid) is None
