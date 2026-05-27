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
from urllib.parse import urlparse, parse_qs

from credenza.rest import authorize as az
from credenza.rest import login as lf
from credenza.api.auth.client.client_registry import ClientRegistry, ClientRecord
from credenza.api.session.storage.session_store import SessionType


# ---------------------------------------------------------------------------
# Stub OIDC client
# ---------------------------------------------------------------------------

class StubOIDCClient:
    def __init__(self, *, tokens=None, userinfo=None, scope="openid email profile"):
        self.scope = scope
        self._tokens = tokens or {}
        self._userinfo = userinfo or {}
        self.logout_url = "https://idp/logout"

    def create_authorization_url(self, **kwargs):
        state = kwargs.get("state", "stub-state")
        return (f"https://idp.example/auth?state={state}", None, "stub-verifier")

    def exchange_code_for_tokens(self, code, redirect_uri, code_verifier):
        return self._tokens

    def validate_id_token(self, id_token, nonce):
        return self._userinfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_REDIRECT_URI = "https://client.example/callback"
_RESOURCE = "https://api.example/"


def _make_client_rec(**kwargs):
    defaults = dict(
        client_id="test-client",
        public=True,
        enabled=True,
        allowed_grant_types=["authorization_code"],
        allowed_redirect_uris=[_REDIRECT_URI],
        allowed_resources=[_RESOURCE],
        allowed_scopes=["openid", "email"],
        default_resources=[],
        default_scopes=[],
    )
    defaults.update(kwargs)
    return ClientRecord(**defaults)


def _base_params(**overrides):
    params = dict(
        client_id="test-client",
        redirect_uri=_REDIRECT_URI,
        response_type="code",
        scope="openid",
        code_challenge="abc123challengevalue_base64url_padded_12345",
        code_challenge_method="S256",
        state="client-state-xyz",
        resource=_RESOURCE,
    )
    params.update(overrides)
    return params


def _store_oauth_ctx(store, app, state, *, created_at=None, **overrides):
    """Store a complete OAuth authn_request_ctx for /callback testing."""
    now = int(time.time())
    ctx = {
        "nonce": "nonce123",
        "code_verifier": "verif123",
        "scope": "openid email",
        "realm": app.config["DEFAULT_REALM"],
        "referrer": None,
        "redirect_uri": f"{app.config['BASE_URL']}/callback",
        "created_at": int(created_at if created_at is not None else now),
        "oauth_client_id":             "test-client",
        "oauth_redirect_uri":          _REDIRECT_URI,
        "oauth_state":                 "client-state-xyz",
        "oauth_scope":                 "openid email",
        "oauth_resources":             [_RESOURCE],
        "oauth_code_challenge":        "abc123challenge",
        "oauth_code_challenge_method": "S256",
        "oauth_session_ttl":           3600,
    }
    ctx.update(overrides)
    store.set_authn_request_ctx(state, ctx)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def client_rec():
    return _make_client_rec()


@pytest.fixture
def registry(client_rec):
    return ClientRegistry(version="1", clients={"test-client": client_rec})


@pytest.fixture
def stub_oidc():
    return StubOIDCClient(
        tokens={
            "id_token": "id.tok",
            "access_token": "at",
            "scope": "openid email",
        },
        userinfo={"sub": "u1", "email": "u@example.com"},
    )


@pytest.fixture
def client(app, registry, stub_oidc, monkeypatch):
    app.testing = True
    app.config["CLIENT_REGISTRY"] = registry
    app.config["ENABLE_PKCE"] = True
    app.register_blueprint(az.authorize_blueprint)
    app.register_blueprint(lf.login_blueprint)
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda r, **kw: stub_oidc)
    return app.test_client()


# ===========================================================================
# /authorize endpoint tests
# ===========================================================================

def test_authorize_missing_client_id(client):
    resp = client.get("/authorize?redirect_uri=https://x.example/cb&response_type=code")
    assert resp.status_code == 400


def test_authorize_unknown_client(client):
    resp = client.get("/authorize?client_id=unknown&redirect_uri=https://x.example/cb&response_type=code")
    assert resp.status_code == 401


def test_authorize_missing_redirect_uri(client):
    resp = client.get("/authorize?client_id=test-client&response_type=code")
    assert resp.status_code == 400


def test_authorize_redirect_uri_not_registered(client):
    resp = client.get("/authorize?client_id=test-client&redirect_uri=https://evil.example/cb&response_type=code")
    assert resp.status_code == 400


def test_authorize_grant_not_allowed(app, stub_oidc, monkeypatch):
    """Client without authorization_code grant -> redirect error unauthorized_client."""
    rec = _make_client_rec(allowed_grant_types=["client_credentials"])
    registry = ClientRegistry(version="1", clients={"test-client": rec})
    app.testing = True
    app.config["CLIENT_REGISTRY"] = registry
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda r, **kw: stub_oidc)
    app.register_blueprint(az.authorize_blueprint)
    c = app.test_client()
    resp = c.get("/authorize", query_string=_base_params())
    assert resp.status_code == 302
    loc = urlparse(resp.headers["Location"])
    qs = parse_qs(loc.query)
    assert qs["error"][0] == "unauthorized_client"
    assert qs["state"][0] == "client-state-xyz"


def test_authorize_wrong_response_type(client):
    p = _base_params(response_type="token")
    resp = client.get("/authorize", query_string=p)
    assert resp.status_code == 302
    qs = parse_qs(urlparse(resp.headers["Location"]).query)
    assert qs["error"][0] == "unsupported_response_type"


def test_authorize_public_missing_pkce(client):
    p = _base_params()
    del p["code_challenge"]
    del p["code_challenge_method"]
    resp = client.get("/authorize", query_string=p)
    assert resp.status_code == 302
    qs = parse_qs(urlparse(resp.headers["Location"]).query)
    assert qs["error"][0] == "invalid_request"


def test_authorize_public_wrong_pkce_method(client):
    p = _base_params(code_challenge_method="plain")
    resp = client.get("/authorize", query_string=p)
    assert resp.status_code == 302
    qs = parse_qs(urlparse(resp.headers["Location"]).query)
    assert qs["error"][0] == "invalid_request"


def test_authorize_scope_violation(client):
    p = _base_params(scope="openid email admin")
    resp = client.get("/authorize", query_string=p)
    assert resp.status_code == 302
    qs = parse_qs(urlparse(resp.headers["Location"]).query)
    assert qs["error"][0] == "invalid_scope"


def test_authorize_resource_violation(client):
    p = _base_params(resource="https://evil.example/")
    resp = client.get("/authorize", query_string=p)
    assert resp.status_code == 302
    qs = parse_qs(urlparse(resp.headers["Location"]).query)
    assert qs["error"][0] == "invalid_target"


def test_authorize_success_redirects_to_idp(client, store):
    resp = client.get("/authorize", query_string=_base_params())
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    assert "idp.example/auth" in loc


def test_authorize_stores_oauth_context(client, store):
    resp = client.get("/authorize", query_string=_base_params())
    assert resp.status_code == 302
    # Extract the oidc_state from the IDP redirect URL
    oidc_state = parse_qs(urlparse(resp.headers["Location"]).query)["state"][0]
    ctx = store.get_authn_request_ctx(oidc_state)
    assert ctx is not None
    assert ctx["oauth_client_id"] == "test-client"
    assert ctx["oauth_redirect_uri"] == _REDIRECT_URI
    assert ctx["oauth_state"] == "client-state-xyz"
    assert _RESOURCE in ctx["oauth_resources"]
    assert ctx["oauth_code_challenge"] == "abc123challengevalue_base64url_padded_12345"
    assert ctx["oauth_code_challenge_method"] == "S256"


def test_authorize_default_resources_when_none_requested(client, store):
    """When no resource param given, client default_resources are used."""
    rec = _make_client_rec(
        default_resources=[_RESOURCE],
    )
    reg = ClientRegistry(version="1", clients={"test-client": rec})
    client.application.config["CLIENT_REGISTRY"] = reg
    p = _base_params()
    del p["resource"]
    resp = client.get("/authorize", query_string=p)
    assert resp.status_code == 302
    oidc_state = parse_qs(urlparse(resp.headers["Location"]).query)["state"][0]
    ctx = store.get_authn_request_ctx(oidc_state)
    assert _RESOURCE in ctx["oauth_resources"]


def test_authorize_confidential_client_no_pkce_ok(app, registry, stub_oidc, monkeypatch):
    """Confidential (non-public) client may omit PKCE."""
    rec = _make_client_rec(public=False)
    reg = ClientRegistry(version="1", clients={"test-client": rec})
    app.testing = True
    app.config["CLIENT_REGISTRY"] = reg
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda r, **kw: stub_oidc)
    app.register_blueprint(az.authorize_blueprint)
    c = app.test_client()
    p = dict(
        client_id="test-client",
        redirect_uri=_REDIRECT_URI,
        response_type="code",
        scope="openid",
        state="st",
        resource=_RESOURCE,
    )
    resp = c.get("/authorize", query_string=p)
    assert resp.status_code == 302
    assert "idp.example/auth" in resp.headers["Location"]


def test_authorize_confidential_client_wrong_pkce_method(app, stub_oidc, monkeypatch):
    """Confidential client that supplies PKCE must use S256."""
    rec = _make_client_rec(public=False)
    reg = ClientRegistry(version="1", clients={"test-client": rec})
    app.testing = True
    app.config["CLIENT_REGISTRY"] = reg
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda r, **kw: stub_oidc)
    app.register_blueprint(az.authorize_blueprint)
    c = app.test_client()
    p = dict(
        client_id="test-client",
        redirect_uri=_REDIRECT_URI,
        response_type="code",
        scope="openid",
        code_challenge="challenge",
        code_challenge_method="plain",
        resource=_RESOURCE,
    )
    resp = c.get("/authorize", query_string=p)
    assert resp.status_code == 302
    qs = parse_qs(urlparse(resp.headers["Location"]).query)
    assert qs["error"][0] == "invalid_request"


def test_authorize_oidc_client_init_fails(app, registry, monkeypatch):
    """OIDC client init failure -> 502."""
    app.testing = True
    app.config["CLIENT_REGISTRY"] = registry
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda r, **kw: (_ for _ in ()).throw(RuntimeError("broken")))
    app.register_blueprint(az.authorize_blueprint)
    c = app.test_client()
    resp = c.get("/authorize", query_string=_base_params())
    assert resp.status_code == 502


# ===========================================================================
# /callback OAuth branch tests
# ===========================================================================

def test_callback_oauth_flow_redirects_to_client(client, store):
    """OAuth callback issues auth code and redirects to client redirect_uri."""
    oidc_state = "oidc-state-abc"
    _store_oauth_ctx(store, client.application, oidc_state)
    resp = client.get(f"/callback?code=authz_code_from_idp&state={oidc_state}")
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    assert loc.startswith(_REDIRECT_URI)
    qs = parse_qs(urlparse(loc).query)
    assert "code" in qs
    assert qs["state"][0] == "client-state-xyz"


def test_callback_oauth_flow_no_cookie(client, store):
    """OAuth flow must NOT set a session cookie."""
    oidc_state = "oidc-state-nocookie"
    _store_oauth_ctx(store, client.application, oidc_state)
    resp = client.get(f"/callback?code=x&state={oidc_state}")
    assert resp.status_code == 302
    assert "credenza-test" not in resp.headers.get("Set-Cookie", "")


def test_callback_oauth_code_payload(client, store):
    """Auth code payload stored in store has expected fields."""
    oidc_state = "oidc-state-payload"
    _store_oauth_ctx(store, client.application, oidc_state)
    resp = client.get(f"/callback?code=x&state={oidc_state}")
    assert resp.status_code == 302
    # Extract code from redirect
    loc = resp.headers["Location"]
    auth_code = parse_qs(urlparse(loc).query)["code"][0]
    payload = store.consume_authorization_code(auth_code)
    assert payload is not None
    assert payload["client_id"] == "test-client"
    assert payload["redirect_uri"] == _REDIRECT_URI
    assert payload["code_challenge"] == "abc123challenge"
    assert payload["code_challenge_method"] == "S256"
    assert _RESOURCE in payload["resources"]
    assert "session_id" in payload
    assert "issued_at" in payload


def test_callback_oauth_session_has_resources(client, store):
    """Session created in OAuth flow carries allowed_resources."""
    oidc_state = "oidc-state-resources"
    _store_oauth_ctx(store, client.application, oidc_state)
    resp = client.get(f"/callback?code=x&state={oidc_state}")
    assert resp.status_code == 302
    loc = resp.headers["Location"]
    auth_code = parse_qs(urlparse(loc).query)["code"][0]
    payload = store.consume_authorization_code(auth_code)
    sid = payload["session_id"]
    session = store.get_session_data(sid)
    assert session is not None
    assert _RESOURCE in session.allowed_resources


def test_callback_oauth_state_consumed(client, store):
    """authn_request_ctx is deleted from store after OAuth callback."""
    oidc_state = "oidc-state-consumed"
    _store_oauth_ctx(store, client.application, oidc_state)
    client.get(f"/callback?code=x&state={oidc_state}")
    assert store.get_authn_request_ctx(oidc_state) is None


def test_callback_regular_flow_unchanged(client, store):
    """Regular (non-OAuth) login callback still sets cookie and redirects normally."""
    state = "regular-state"
    store.set_authn_request_ctx(state, {
        "nonce": "nonce123",
        "code_verifier": "verif123",
        "scope": "openid email",
        "realm": client.application.config["DEFAULT_REALM"],
        "referrer": "/dashboard",
        "redirect_uri": f"{client.application.config['BASE_URL']}/callback",
        "created_at": int(time.time()),
    })
    resp = client.get(f"/callback?code=x&state={state}")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")
    assert "credenza-test" in resp.headers.get("Set-Cookie", "")