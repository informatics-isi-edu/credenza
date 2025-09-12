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
import time
import uuid
from flask import g
from unittest.mock import Mock
from urllib.parse import urlparse, parse_qs, unquote
from credenza.rest import login_flow as lf
from credenza.api.session.storage.session_store import TRANSIENT_DATA_TTL
from credenza.api.oidc_client import OIDCClient
from credenza.api.session.storage.session_store import SessionData
from credenza.rest.login_flow import callback

class StubOIDCClient:
    def __init__(self, *, tokens, userinfo, scope="openid email profile"):
        self.scope = scope
        self._tokens = tokens
        self._userinfo = userinfo
        self.logout_url = "https://idp/logout"

    def create_authorization_url(self, **kwargs):
        # return (auth_url, auth_state, code_verifier)
        return ("https://idp.example/auth", None, "stub-verifier")

    def exchange_code_for_tokens(self, code, redirect_uri, code_verifier):
        return self._tokens

    def validate_id_token(self, id_token, nonce):
        return self._userinfo

class _StubClientRaises:
    """OIDC client whose token exchange always raises."""
    def __init__(self, exc):
        self._exc = exc
        self.scope = "openid email"
    def create_authorization_url(self, **kwargs):
        # not used here, but keep shape consistent
        return ("https://idp.example/auth", None, "cv")
    def exchange_code_for_tokens(self, code, redirect_uri, code_verifier):
        raise self._exc
    def validate_id_token(self, id_token, nonce):
        return {}

def _store_ctx(store, app, state, *, created_at=None):
    """Stores a minimal-but-complete authn_request_ctx the route expects."""
    now = int(time.time())
    store.store_authn_request_ctx(state, {
        "nonce": "nonce123",
        "code_verifier": "verif123",
        "scope": "openid email",
        "realm": app.config["DEFAULT_REALM"],
        "referrer": "/",
        "redirect_uri": f"{app.config['BASE_URL']}/callback",
        "created_at": int(created_at if created_at is not None else now),
    })

@pytest.fixture
def client(app, monkeypatch):
    app.testing = True
    app.register_blueprint(lf.login_blueprint)
    return app.test_client()

def test_login_existing(client, monkeypatch):
    monkeypatch.setattr(lf, "has_current_session", lambda: "existing")
    resp = client.get("/login")
    assert resp.status_code == 302

def test_login_redirect(client, app, store, monkeypatch):
    class Stub(StubOIDCClient):
        def create_authorization_url(self, **kw):
            return ("https://idp/auth?state="+kw["state"], None, "cv")
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client", lambda r: Stub(tokens={}, userinfo={}))
    resp = client.get("/login?referrer=/home")
    assert resp.status_code == 302
    state = parse_qs(urlparse(resp.headers["Location"]).query)["state"][0]
    ctx = store.get_authn_request_ctx(state)
    assert ctx["referrer"] == "/home"


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

def test_callback_missing_nonce(client, app, store, monkeypatch):
    # store context without nonce to trigger 400
    state = uuid.uuid4().hex
    realm = app.config["DEFAULT_REALM"]
    redirect_uri = f"{app.config['BASE_URL']}/callback"
    store.store_authn_request_ctx(state, {
        "code_verifier": "verif",
        "realm": realm,
        "referrer": "/dest",
        "redirect_uri": redirect_uri,
        "scope": "openid",
        "created_at": int(time.time()),
    })

    # stub client so we don't hit network
    stub = StubOIDCClient(tokens={"id_token": "id", "access_token": "x", "scope": "openid"},
                          userinfo={"sub": "u", "email": "e@example.com"})
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client", lambda r: stub)

    resp = client.get("/callback", query_string={"code": "code123", "state": state})
    assert resp.status_code == 400

def test_callback_success(client, app, store, monkeypatch, frozen_time):
    code = "code123"
    nonce = "n123"
    verifier = "v123"
    state = uuid.uuid4().hex

    # New: store a full context the route needs
    realm = app.config["DEFAULT_REALM"]
    redirect_uri = f"{app.config['BASE_URL']}/callback"
    ctx = {
        "nonce": nonce,
        "code_verifier": verifier,
        "referrer": "/after",
        "realm": realm,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "created_at": int(time.time()),
    }
    store.store_authn_request_ctx(state, ctx)

    token_dict = {
        "id_token": "idtok",
        "access_token": "acc",
        "refresh_token": "rtok",
        "scope": "openid email profile",
        "refresh_expires_in": 0,
    }
    userinfo = {
        "sub": "user1",
        "email": "user1@example.com",
        "preferred_username": "user1",
        "name": "User One",
        "email_verified": True,
        "iss": "https://issuer",
        "aud": ["cid"],
        "groups": [],
        "roles": [],
    }

    # New: stub the factory to return our stub client (so no network)
    stub = StubOIDCClient(tokens=token_dict, userinfo=userinfo)
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client", lambda _realm: stub)

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

def test_logout_uses_client_logout_and_profile(client, app, store, monkeypatch):
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
        "test": {"logout_url_params": {"foo": "bar"}}
    }

    stub = StubOIDCClient(tokens=None, userinfo=None)
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client", lambda _realm: stub)
    resp = client.get("/logout")
    assert resp.status_code in (302, 303)
    loc = resp.headers["Location"]
    assert loc.startswith(stub.logout_url)
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

    # New: ensure the route has a stored context
    state = uuid.uuid4().hex
    realm = "test"
    redirect_uri = f"{app.config['BASE_URL']}/callback"
    store.store_authn_request_ctx(state, {
        "nonce": "nonce123",
        "code_verifier": "verif123",
        "realm": realm,
        "referrer": "/",
        "redirect_uri": redirect_uri,
        "scope": "openid email",
        "created_at": int(time.time()),
    })

    # Keep your augmentation toggle
    call_count = {"count": 0}
    def mock_augment(tokens, realm, userinfo, metadata):
        call_count["count"] += 1
        if call_count["count"] == 1:
            metadata["augmentation_deferred"] = True
            return userinfo, {}
        else:
            return {"sub": "123", "email": "u@example.com", "groups": ["g1"]}, {"foo": "bar"}

    monkeypatch.setattr("credenza.rest.login_flow.augment_session", mock_augment)
    monkeypatch.setattr("credenza.api.util.get_augmentation_provider_params",
                        lambda realm: {"defer_augmentation": True})

    # New: stub the client via the factory (instance patch is safer)
    stub = StubOIDCClient(tokens=dummy_tokens, userinfo=dummy_userinfo, scope="openid email")
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client", lambda r: stub)

    update_mock = Mock()
    monkeypatch.setattr(store, "update_session", update_mock)
    monkeypatch.setattr(store, "generate_session_id", lambda: sid)
    monkeypatch.setattr(store, "create_session", lambda **kwargs: (session_key, base_session))

    with app.test_request_context(f"/callback?code=abc&state={state}"):
        g.session_key = session_key
        resp = callback()

    assert resp.status_code == 302
    assert resp.location.endswith("/")
    assert call_count["count"] == 2
    update_mock.assert_called_once()
    updated_sid, updated_session = update_mock.call_args[0]
    assert updated_sid == sid
    assert updated_session.userinfo["groups"] == ["g1"]
    assert updated_session.additional_tokens == {"foo": "bar"}

def test_callback_token_exchange_transient_preserves_ctx(client, app, store, monkeypatch):
    state = uuid.uuid4().hex
    # Leave ~30s remaining so we hit the preserve path with ttl=min(60, remaining)
    created_at = int(time.time()) - (TRANSIENT_DATA_TTL - 30)
    _store_ctx(store, app, state, created_at=created_at)

    # Classify as transient and stub the client to raise
    monkeypatch.setattr(lf, "is_transient_request_error", lambda e: True)
    stub = _StubClientRaises(RuntimeError("upstream timeout"))
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client", lambda realm: stub)

    resp = client.get("/callback", query_string={"code": "abc", "state": state})
    assert resp.status_code == 502

    # Context should still be present (preserved)
    assert store.get_authn_request_ctx(state) is not None


def test_callback_token_exchange_transient_but_state_expired(client, app, store, monkeypatch):
    state = uuid.uuid4().hex
    # Make remaining == 0
    created_at = int(time.time()) - TRANSIENT_DATA_TTL
    _store_ctx(store, app, state, created_at=created_at)

    monkeypatch.setattr(lf, "is_transient_request_error", lambda e: True)
    stub = _StubClientRaises(RuntimeError("idp 5xx"))
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client", lambda realm: stub)

    resp = client.get("/callback", query_string={"code": "abc", "state": state})
    assert resp.status_code == 400
    assert b"State expired" in resp.data

def test_callback_token_exchange_non_transient_deletes_ctx(client, app, store, monkeypatch):
    state = uuid.uuid4().hex
    _store_ctx(store, app, state)

    monkeypatch.setattr(lf, "is_transient_request_error", lambda e: False)
    stub = _StubClientRaises(ValueError("invalid_grant"))
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client", lambda realm: stub)

    resp = client.get("/callback", query_string={"code": "abc", "state": state})
    assert resp.status_code == 400
    assert b"Token exchange failed" in resp.data

    # Context should be gone due to finally-block deletion on non-transient errors
    assert store.get_authn_request_ctx(state) is None


