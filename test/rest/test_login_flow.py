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
import json
import base64
from flask import g
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qs, unquote
from credenza.rest import login_flow as lf
from credenza.api.oidc_client import OIDCClient
from credenza.api.session.storage.session_store import SessionData
from credenza.rest.login_flow import callback

class DummyAuthSession:
    def create_authorization_url(self, url, state, nonce, redirect_uri, code_verifier):
        return (
            f"{url}?state={state}&nonce={nonce}&redirect_uri={redirect_uri}, code_verifier={code_verifier}",
            None
        )

@pytest.fixture
def client(app, monkeypatch):
    app.testing = True
    app.register_blueprint(lf.login_blueprint)
    return app.test_client()

def test_login_conflict(client, monkeypatch):
    monkeypatch.setattr(lf, "has_current_session", lambda: "existing")
    resp = client.get("/login")
    assert resp.status_code == 409

def test_login_redirect(client, app, store, monkeypatch):
    monkeypatch.setattr(lf, "has_current_session", lambda: None)
    monkeypatch.setattr(
        OIDCClient,
        "get_oauth_session",
        lambda *args, **kwargs: DummyAuthSession()
    )

    resp = client.get("/login?referrer=/home")
    assert resp.status_code == 302
    location = resp.headers["Location"]
    parsed = urlparse(location)
    qs = parse_qs(parsed.query)
    state = qs["state"][0]
    nonce = qs["nonce"][0]
    assert store.get_nonce(state) == nonce
    decoded = json.loads(base64.urlsafe_b64decode(state).decode())
    assert decoded["referrer"] == "/home"

@pytest.mark.parametrize("missing", ["none", "code", "state"])
def test_callback_bad_request(client, missing, monkeypatch):
    params = {}
    if missing != "code":
        params["code"] = "c"
    if missing != "state":
        params["state"] = "s"

    monkeypatch.setattr(
        OIDCClient,
        "exchange_code_for_tokens",
        lambda self, c, s, v: dict()
    )
    resp = client.get("/callback", query_string=params)
    assert resp.status_code == 400

def test_callback_missing_nonce(client, app, monkeypatch):
    code = "code123"
    payload = {"nonce": "n", "referrer": "/dest"}
    state = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()

    monkeypatch.setattr(
        OIDCClient,
        "exchange_code_for_tokens",
        lambda self, c, s, v: dict()
    )
    resp = client.get("/callback", query_string={"code": code, "state": state})
    assert resp.status_code == 400

def test_callback_success(client, app, store, monkeypatch, frozen_time):
    code = "code123"
    nonce = "n123"
    payload = {"nonce": nonce, "referrer": "/after"}
    state = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    store.store_nonce(state, nonce)
    # since PKCE is on by default, we must supply a verifier
    store.store_pkce_verifier(state, "VERIFIER123")

    token_dict = {
        "id_token": "idtok",
        "access_token": "acc",
        "refresh_token": "rtok",
        "scope": "openid email profile",
        "refresh_expires_in": 0
    }
    monkeypatch.setattr(
        OIDCClient,
        "exchange_code_for_tokens",
        lambda self, c, s, v: token_dict
    )
    userinfo = {
        "sub": "user1",
        "email": "user1@example.com",
        "preferred_username": "user1",
        "name": "User One",
        "email_verified": True,
        "iss": "https://issuer",
        "aud": ["cid"],
        "groups": [],
        "roles": []
    }
    monkeypatch.setattr(
        OIDCClient,
        "validate_id_token",
        lambda self, idt, nn: userinfo
    )
    provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("default")
    monkeypatch.setattr(provider, "process_additional_tokens", lambda t, now: {})
    monkeypatch.setattr(provider, "enrich_userinfo", lambda ui, ext: None)

    resp = client.get("/callback", query_string={"code": code, "state": state})
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/after"
    cookie_hdr = resp.headers["Set-Cookie"].split(";")[0]
    cookie_val = cookie_hdr.split("=", 1)[1]
    sid, session = store.get_session_by_session_key(cookie_val)
    assert isinstance(session, SessionData)
    assert session.access_token == "acc"

def test_logout_no_session(client, monkeypatch):
    monkeypatch.setattr(lf, "has_current_session", lambda: None)
    resp = client.get("/logout")
    assert resp.status_code in (302, 303)
    assert urlparse(resp.headers["Location"]).path == "/"

def test_logout_normal(client, app, store, monkeypatch, fake_current_session):
    monkeypatch.setattr(lf, "revoke_tokens", lambda sid, session: None)
    monkeypatch.setattr(lf, "has_current_session", lambda: "fake_current_sid")
    resp = client.get("/logout")
    assert resp.status_code in (302, 303)
    assert "/" == urlparse(resp.headers["Location"]).path
    assert "Expires=Thu, 01 Jan 1970" in resp.headers["Set-Cookie"]

def test_logout_with_profile(client, app, store, monkeypatch):
    sid = "sid"
    monkeypatch.setattr(lf, "has_current_session", lambda: sid)
    monkeypatch.setattr(lf, "revoke_tokens", lambda sid, session: None)
    store.create_session(sid,
                         access_token="at",
                         userinfo={"sub": "u"},
                         realm="test",
                         id_token="id",
                         refresh_token="rt",
                         scopes="openid")
    app.config["OIDC_IDP_PROFILES"] = {
        "test": {"logout_url": "https://idp/logout", "logout_url_params": {"foo": "bar"}}
    }
    resp = client.get("/logout")
    assert resp.status_code in (302, 303)
    loc = resp.headers["Location"]
    assert loc.startswith("https://idp/logout")
    qs = parse_qs(urlparse(loc).query)
    assert qs["foo"] == ["bar"]

def test_preauth_json_and_redirect(client, app):
    app.config["POST_LOGIN_REDIRECT"] = "/home"
    resp = client.get("/preauth")
    assert resp.status_code == 200
    data = resp.get_json()
    url = data["redirect_url"]
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    assert unquote(qs["referrer"][0]) == "/home"

    resp2 = client.get("/preauth?do_redirect=1&referrer=/foo")
    assert resp2.status_code == 303
    loc = resp2.headers["Location"]
    parsed2 = urlparse(loc)
    qs2 = parse_qs(parsed2.query)
    assert unquote(qs2["referrer"][0]) == "/foo"

def test_callback_deferred_augmentation(app, base_session, monkeypatch):
    store = app.config["SESSION_STORE"]
    sid = "deferred-sid"
    session_key = "deferred-session-key"

    dummy_tokens = {"id_token": "id", "access_token": "atk", "scope": "openid email"}
    dummy_userinfo = {"sub": "123", "email": "u@example.com"}
    dummy_augmented_userinfo = {"sub": "123", "email": "u@example.com", "groups": ["g1"]}
    dummy_additional_tokens = {"foo": "bar"}

    call_count = {"count": 0}
    def mock_augment(tokens, realm, userinfo, metadata):
        print ("Mock augment called")
        call_count["count"] += 1
        if call_count["count"] == 1:
            metadata["augmentation_deferred"] = True
            return userinfo, {}
        else:
            return dummy_augmented_userinfo, dummy_additional_tokens

    monkeypatch.setattr("credenza.rest.login_flow.augment_session", mock_augment)
    monkeypatch.setattr("credenza.api.util.get_augmentation_provider_params",
                        lambda realm: {"defer_augmentation": True})

    client = app.config["OIDC_CLIENT_FACTORY"].get_client("test")
    monkeypatch.setattr(client, "exchange_code_for_tokens", lambda *a, **kw: dummy_tokens)
    monkeypatch.setattr(client, "validate_id_token", lambda token, nonce: dummy_userinfo)

    update_mock = Mock()
    monkeypatch.setattr(store, "update_session", update_mock)
    monkeypatch.setattr(store, "get_nonce", lambda state: "nonce")
    monkeypatch.setattr(store, "delete_nonce", lambda state: None)
    monkeypatch.setattr(store, "get_pkce_verifier", lambda state: "code_verifier")
    monkeypatch.setattr(store, "delete_pkce_verifier", lambda state: None)
    monkeypatch.setattr(store, "generate_session_id", lambda: sid)
    monkeypatch.setattr(store, "create_session", lambda **kwargs: (session_key, base_session))

    encoded_state = base64.urlsafe_b64encode(json.dumps({"nonce": "nonce", "referrer": "/"}).encode()).decode()
    with app.test_request_context(f"/callback?code=abc&state={encoded_state}"):
        g.session_key = session_key
        resp = callback()

    assert resp.status_code == 302
    assert resp.location.endswith("/")
    assert call_count["count"] == 2
    update_mock.assert_called_once()

    updated_sid, updated_session = update_mock.call_args[0]
    assert updated_sid == sid
    assert updated_session.userinfo == dummy_augmented_userinfo
    assert updated_session.additional_tokens == dummy_additional_tokens

