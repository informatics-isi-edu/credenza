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

from credenza.rest import consent as cv
from credenza.rest import login as lf
from credenza.api.auth.client.client_registry import ClientRegistry, ClientRecord
from credenza.api.session.storage.session_store import SessionStore, SessionType


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_REDIRECT_URI = "https://client.example/callback"
_RESOURCE = "https://api.example/"        # what test-client is allowed to access
_RS_RESOURCE = "https://rs.example/"      # the RS's own protected resource URI
_EXCHANGE_TARGET = "https://downstream.example/"
_BASE_URL = "https://localhost"
_SUB = "u1"
_ISS = "https://idp.example"
_PRINCIPAL = f"{_ISS}/{_SUB}"


# ---------------------------------------------------------------------------
# Stubs
# ---------------------------------------------------------------------------

class StubOIDCClient:
    def __init__(self, *, tokens=None, userinfo=None, scope="openid email"):
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


def _make_rs_rec(**kwargs):
    defaults = dict(
        client_id="test-rs",
        public=False,
        enabled=True,
        allowed_grant_types=["token_exchange"],
        allowed_resources=[_RS_RESOURCE],     # distinct URI from _RESOURCE
        allowed_token_exchange_targets=[_EXCHANGE_TARGET],
        default_resources=[],
        default_scopes=[],
    )
    defaults.update(kwargs)
    return ClientRecord(**defaults)


def _make_registry(client_rec, rs_rec=None):
    clients = {"test-client": client_rec}
    if rs_rec:
        clients["test-rs"] = rs_rec
    resource_index = {}
    for cr in clients.values():
        for r in cr.allowed_resources:
            if r not in resource_index:
                resource_index[r] = cr
    return ClientRegistry(
        version="1",
        clients=clients,
        resource_index=resource_index,
    )


def _store_oauth_ctx(store, app, state, **overrides):
    now = int(time.time())
    ctx = {
        "nonce": "nonce123",
        "code_verifier": "verif123",
        "scope": "openid email",
        "realm": app.config["DEFAULT_REALM"],
        "referrer": None,
        "redirect_uri": f"{app.config['BASE_URL']}/callback",
        "created_at": now,
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


def _default_tokens():
    return {
        "id_token": "id.tok",
        "access_token": "at",
        "scope": "openid email",
    }


def _default_userinfo():
    return {"sub": _SUB, "email": "u@example.com", "iss": _ISS}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store():
    from credenza.api.session.storage.backends.memory import MemoryBackend
    return SessionStore(backend=MemoryBackend(), ttl=2100)


@pytest.fixture
def stub_oidc():
    return StubOIDCClient(tokens=_default_tokens(), userinfo=_default_userinfo())


@pytest.fixture
def client_rec():
    return _make_client_rec()


@pytest.fixture
def consent_client_rec():
    return _make_client_rec(require_consent=True, consent_display_name="Test App")


@pytest.fixture
def rs_rec():
    return _make_rs_rec()


# ---------------------------------------------------------------------------
# is_consent_needed unit tests
# ---------------------------------------------------------------------------

class TestIsConsentNeeded:
    def test_needed_when_no_auth_consent(self, store):
        registry = _make_registry(_make_client_rec())
        assert cv.is_consent_needed(store, registry, _PRINCIPAL, "test-client", []) is True

    def test_not_needed_when_auth_consent_present(self, store):
        store.set_consent_auth(_PRINCIPAL, "test-client")
        registry = _make_registry(_make_client_rec())
        assert cv.is_consent_needed(store, registry, _PRINCIPAL, "test-client", []) is False

    def test_needed_when_deleg_consent_missing(self, store):
        store.set_consent_auth(_PRINCIPAL, "test-client")
        rs_rec = _make_rs_rec()
        registry = _make_registry(_make_client_rec(), rs_rec=rs_rec)
        assert cv.is_consent_needed(store, registry, _PRINCIPAL, "test-client", [_RS_RESOURCE]) is True

    def test_not_needed_when_both_consents_present(self, store):
        store.set_consent_auth(_PRINCIPAL, "test-client")
        store.set_consent_deleg(_PRINCIPAL, _RS_RESOURCE)
        rs_rec = _make_rs_rec()
        registry = _make_registry(_make_client_rec(), rs_rec=rs_rec)
        assert cv.is_consent_needed(store, registry, _PRINCIPAL, "test-client", [_RS_RESOURCE]) is False

    def test_no_deleg_check_when_rs_has_no_targets(self, store):
        store.set_consent_auth(_PRINCIPAL, "test-client")
        rs_rec = _make_rs_rec(allowed_token_exchange_targets=[])
        registry = _make_registry(_make_client_rec(), rs_rec=rs_rec)
        assert cv.is_consent_needed(store, registry, _PRINCIPAL, "test-client", [_RS_RESOURCE]) is False

    def test_no_deleg_check_when_resource_not_in_index(self, store):
        store.set_consent_auth(_PRINCIPAL, "test-client")
        registry = _make_registry(_make_client_rec())  # no RS in index
        assert cv.is_consent_needed(store, registry, _PRINCIPAL, "test-client", [_RS_RESOURCE]) is False


# ---------------------------------------------------------------------------
# Consent label merge tests (CONSENT_LABELS config + per-client override)
# ---------------------------------------------------------------------------

class TestConsentLabelMerge:
    def test_global_labels_shown(self, flask_app, store):
        rec = _make_client_rec(require_consent=True)
        flask_app.config["CLIENT_REGISTRY"] = _make_registry(rec)
        store.set_pending_consent("lbl1", {
            "session_id": "s", "sub": _SUB, "principal": _PRINCIPAL,
            "client_id": "test-client", "redirect_uri": _REDIRECT_URI,
            "oauth_state": "", "scope": "openid email",
            "resources": [], "realm": "test",
        })
        with flask_app.test_client() as c:
            body = c.get("/authorize/consent?pending=lbl1").data.decode()
        assert "Verify your identity" in body
        assert "Your email" in body

    def test_per_client_overrides_global(self, flask_app, store):
        rec = _make_client_rec(require_consent=True,
                               consent_labels={"openid": "Custom identity label"})
        flask_app.config["CLIENT_REGISTRY"] = _make_registry(rec)
        store.set_pending_consent("lbl2", {
            "session_id": "s", "sub": _SUB, "principal": _PRINCIPAL,
            "client_id": "test-client", "redirect_uri": _REDIRECT_URI,
            "oauth_state": "", "scope": "openid",
            "resources": [], "realm": "test",
        })
        with flask_app.test_client() as c:
            body = c.get("/authorize/consent?pending=lbl2").data.decode()
        assert "Custom identity label" in body
        assert "Verify your identity" not in body


# ---------------------------------------------------------------------------
# Callback consent redirect tests (integration via test client)
# ---------------------------------------------------------------------------

@pytest.fixture
def flask_app(store, stub_oidc, monkeypatch):
    from flask import Flask
    from werkzeug.utils import import_string
    from werkzeug.exceptions import HTTPException
    from credenza.api.auth.oidc_client import OIDCClientFactory, OIDCClient
    from credenza.api.common.rate_limit import FixedWindowJitterLimiter

    app = Flask(__name__)
    app.testing = True
    app.config["DEFAULT_REALM"] = "test"
    app.config["SESSION_STORE"] = store
    app.config["COOKIE_NAME"] = "credenza-test"
    app.config["CRYPTO_CODEC"] = None
    app.config["OIDC_CLIENT_FACTORY"] = OIDCClientFactory({"test": {
        "client_secret_file": "/dev/null",
        "authorize_url": "https://idp.example/auth",
        "token_url": "https://idp.example/token",
        "userinfo_url": "https://idp.example/userinfo",
        "redirect_uri": "https://localhost/callback",
        "scopes": "openid email",
    }})
    app.config["OIDC_IDP_PROFILES"] = {}
    app.config["ENABLE_LEGACY_API"] = False
    app.config["BASE_URL"] = _BASE_URL
    app.config["SERVER_NAME"] = "localhost"
    app.config["CONSENT_LABELS"] = {"openid": "Verify your identity", "email": "Your email"}
    app.config["ENABLE_PKCE"] = True
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = {
        "test": import_string(
            "credenza.api.session.augmentation.base_provider:DefaultSessionAugmentationProvider"
        )()
    }
    app.extensions["rate_limits"] = {
        "10_per_min": FixedWindowJitterLimiter(limit=10, window_sec=60),
        "30_per_min": FixedWindowJitterLimiter(limit=30, window_sec=60),
        "60_per_min": FixedWindowJitterLimiter(limit=60, window_sec=60),
    }

    discovery = {
        "authorization_endpoint": "https://idp.example/auth",
        "token_endpoint": "https://idp.example/token",
        "userinfo_endpoint": "https://idp.example/userinfo",
        "jwks_uri": "https://idp.example/jwks",
        "issuer": "https://idp.example/",
    }
    monkeypatch.setattr(OIDCClient, "_fetch_discovery_metadata",
                        staticmethod(lambda url: discovery), raising=True)
    monkeypatch.setattr(OIDCClient, "_load_client_secret",
                        lambda self: (setattr(self, "client_id", "cid") or
                                      setattr(self, "client_secret", "secret")))
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda r, **kw: stub_oidc)

    @app.errorhandler(HTTPException)
    def handle_http(e):
        return e.get_response()

    app.register_blueprint(lf.login_blueprint)
    app.register_blueprint(cv.consent_blueprint)
    return app


def _callback_url(state, code="auth-code-123"):
    return f"/callback?code={code}&state={state}"


class TestCallbackConsentRedirect:
    def test_first_party_no_consent_redirect(self, flask_app, store):
        """require_consent=False (default) -- callback issues code directly."""
        rec = _make_client_rec()  # require_consent=False
        registry = _make_registry(rec)
        flask_app.config["CLIENT_REGISTRY"] = registry
        state = "s1"
        _store_oauth_ctx(store, flask_app, state)

        with flask_app.test_client() as c:
            resp = c.get(_callback_url(state))

        assert resp.status_code == 302
        loc = resp.headers["Location"]
        qs = parse_qs(urlparse(loc).query)
        assert "code" in qs
        assert urlparse(loc).netloc == "client.example"

    def test_require_consent_redirects_to_consent_page(self, flask_app, store):
        """require_consent=True with no prior consent -> redirect to /authorize/consent."""
        rec = _make_client_rec(require_consent=True)
        registry = _make_registry(rec)
        flask_app.config["CLIENT_REGISTRY"] = registry
        state = "s2"
        _store_oauth_ctx(store, flask_app, state)

        with flask_app.test_client() as c:
            resp = c.get(_callback_url(state))

        assert resp.status_code == 302
        loc = resp.headers["Location"]
        assert "/authorize/consent" in loc
        assert "pending=" in loc

    def test_consent_reuse_skips_page(self, flask_app, store):
        """Existing valid consent records -> callback issues code without redirect."""
        rec = _make_client_rec(require_consent=True)
        rs_rec = _make_rs_rec()
        registry = _make_registry(rec, rs_rec=rs_rec)
        flask_app.config["CLIENT_REGISTRY"] = registry

        store.set_consent_auth(_PRINCIPAL, "test-client")
        store.set_consent_deleg(_PRINCIPAL, _RS_RESOURCE)

        state = "s3"
        _store_oauth_ctx(store, flask_app, state)

        with flask_app.test_client() as c:
            resp = c.get(_callback_url(state))

        assert resp.status_code == 302
        qs = parse_qs(urlparse(resp.headers["Location"]).query)
        assert "code" in qs


# ---------------------------------------------------------------------------
# GET /authorize/consent tests
# ---------------------------------------------------------------------------

class TestConsentPage:
    def test_missing_pending_param_400(self, flask_app):
        with flask_app.test_client() as c:
            resp = c.get("/authorize/consent")
        assert resp.status_code == 400

    def test_expired_pending_400(self, flask_app):
        with flask_app.test_client() as c:
            resp = c.get("/authorize/consent?pending=nosuchkey")
        assert resp.status_code == 400

    def test_renders_consent_page(self, flask_app, store):
        rec = _make_client_rec(require_consent=True, consent_display_name="My App")
        registry = _make_registry(rec)
        flask_app.config["CLIENT_REGISTRY"] = registry

        store.set_pending_consent("tok1", {
            "session_id": "sid1",
            "sub": _SUB,
            "principal": _PRINCIPAL,
            "client_id": "test-client",
            "redirect_uri": _REDIRECT_URI,
            "oauth_state": "st",
            "scope": "openid email",
            "resources": [_RESOURCE],
            "realm": "test",
        })

        with flask_app.test_client() as c:
            resp = c.get("/authorize/consent?pending=tok1")

        assert resp.status_code == 200
        body = resp.data.decode()
        assert "My App" in body
        assert "Service Access Requested" in body
        assert "Scopes requested" in body
        assert "openid" in body
        assert "email" in body
        assert _RESOURCE in body

    def test_renders_scopes_from_allowed_when_pending_scope_empty(self, flask_app, store):
        """When pending 'scope' is empty, fall back to client's allowed_scopes."""
        rec = _make_client_rec(require_consent=True, allowed_scopes=["openid", "email", "profile"])
        registry = _make_registry(rec)
        flask_app.config["CLIENT_REGISTRY"] = registry

        store.set_pending_consent("tok_noscope", {
            "session_id": "sid_ns",
            "sub": _SUB,
            "principal": _PRINCIPAL,
            "client_id": "test-client",
            "redirect_uri": _REDIRECT_URI,
            "oauth_state": "st",
            "scope": "",
            "resources": [_RESOURCE],
            "realm": "test",
        })

        with flask_app.test_client() as c:
            resp = c.get("/authorize/consent?pending=tok_noscope")

        assert resp.status_code == 200
        body = resp.data.decode()
        assert "Scopes requested" in body
        assert "openid" in body
        assert "email" in body
        assert "profile" in body

    def test_renders_delegation_panel(self, flask_app, store):
        rec = _make_client_rec(require_consent=True)
        rs_rec = _make_rs_rec()
        registry = _make_registry(rec, rs_rec=rs_rec)
        flask_app.config["CLIENT_REGISTRY"] = registry

        store.set_pending_consent("tok2", {
            "session_id": "sid2",
            "sub": _SUB,
            "principal": _PRINCIPAL,
            "client_id": "test-client",
            "redirect_uri": _REDIRECT_URI,
            "oauth_state": "st",
            "scope": "openid",
            "resources": [_RS_RESOURCE],
            "realm": "test",
        })

        with flask_app.test_client() as c:
            resp = c.get("/authorize/consent?pending=tok2")

        assert resp.status_code == 200
        body = resp.data.decode()
        assert _EXCHANGE_TARGET in body

    def test_no_delegation_panel_when_rs_has_no_targets(self, flask_app, store):
        rec = _make_client_rec(require_consent=True)
        rs_rec = _make_rs_rec(allowed_token_exchange_targets=[])
        registry = _make_registry(rec, rs_rec=rs_rec)
        flask_app.config["CLIENT_REGISTRY"] = registry

        store.set_pending_consent("tok3", {
            "session_id": "sid3",
            "sub": _SUB,
            "principal": _PRINCIPAL,
            "client_id": "test-client",
            "redirect_uri": _REDIRECT_URI,
            "oauth_state": "st",
            "scope": "openid",
            "resources": [_RS_RESOURCE],
            "realm": "test",
        })

        with flask_app.test_client() as c:
            resp = c.get("/authorize/consent?pending=tok3")

        assert resp.status_code == 200
        body = resp.data.decode()
        assert "Delegation notice" not in body


# ---------------------------------------------------------------------------
# POST /authorize/consent tests
# ---------------------------------------------------------------------------

class TestConsentSubmit:
    def _make_pending(self, store, token, **overrides):
        data = {
            "session_id": "sid-submit",
            "sub": _SUB,
            "principal": _PRINCIPAL,
            "client_id": "test-client",
            "redirect_uri": _REDIRECT_URI,
            "oauth_state": "client-state",
            "code_challenge": "challenge",
            "code_challenge_method": "S256",
            "scope": "openid email",
            "resources": [_RESOURCE],
            "realm": "test",
        }
        data.update(overrides)
        store.set_pending_consent(token, data)

    def test_deny_redirects_with_access_denied(self, flask_app, store):
        registry = _make_registry(_make_client_rec())
        flask_app.config["CLIENT_REGISTRY"] = registry
        self._make_pending(store, "deny-tok")

        with flask_app.test_client() as c:
            resp = c.post("/authorize/consent",
                          data={"pending": "deny-tok", "action": "deny"})

        assert resp.status_code == 302
        qs = parse_qs(urlparse(resp.headers["Location"]).query)
        assert qs["error"][0] == "access_denied"
        assert qs["state"][0] == "client-state"

    def test_approve_issues_code_and_redirects(self, flask_app, store):
        registry = _make_registry(_make_client_rec())
        flask_app.config["CLIENT_REGISTRY"] = registry
        self._make_pending(store, "approve-tok")

        with flask_app.test_client() as c:
            resp = c.post("/authorize/consent",
                          data={"pending": "approve-tok", "action": "approve"})

        assert resp.status_code == 302
        qs = parse_qs(urlparse(resp.headers["Location"]).query)
        assert "code" in qs
        assert qs["state"][0] == "client-state"

    def test_approve_stores_consent_auth_record(self, flask_app, store):
        registry = _make_registry(_make_client_rec())
        flask_app.config["CLIENT_REGISTRY"] = registry
        self._make_pending(store, "auth-rec-tok")

        with flask_app.test_client() as c:
            c.post("/authorize/consent",
                   data={"pending": "auth-rec-tok", "action": "approve"})

        assert store.get_consent_auth(_PRINCIPAL, "test-client") is not None

    def test_approve_stores_deleg_consent_when_rs_has_targets(self, flask_app, store):
        rs_rec = _make_rs_rec()
        registry = _make_registry(_make_client_rec(), rs_rec=rs_rec)
        flask_app.config["CLIENT_REGISTRY"] = registry
        self._make_pending(store, "deleg-rec-tok", resources=[_RS_RESOURCE])

        with flask_app.test_client() as c:
            c.post("/authorize/consent",
                   data={"pending": "deleg-rec-tok", "action": "approve"})

        assert store.get_consent_deleg(_PRINCIPAL, _RS_RESOURCE) is not None

    def test_approve_no_deleg_consent_when_rs_has_no_targets(self, flask_app, store):
        rs_rec = _make_rs_rec(allowed_token_exchange_targets=[])
        registry = _make_registry(_make_client_rec(), rs_rec=rs_rec)
        flask_app.config["CLIENT_REGISTRY"] = registry
        self._make_pending(store, "no-deleg-tok", resources=[_RS_RESOURCE])

        with flask_app.test_client() as c:
            c.post("/authorize/consent",
                   data={"pending": "no-deleg-tok", "action": "approve"})

        assert store.get_consent_deleg(_PRINCIPAL, _RS_RESOURCE) is None

    def test_pending_consumed_after_approve(self, flask_app, store):
        """Second POST with same pending key returns 400 (atomic consume)."""
        registry = _make_registry(_make_client_rec())
        flask_app.config["CLIENT_REGISTRY"] = registry
        self._make_pending(store, "consumed-tok")

        with flask_app.test_client() as c:
            c.post("/authorize/consent",
                   data={"pending": "consumed-tok", "action": "approve"})
            resp2 = c.post("/authorize/consent",
                           data={"pending": "consumed-tok", "action": "approve"})

        assert resp2.status_code == 400

    def test_missing_pending_key_400(self, flask_app):
        with flask_app.test_client() as c:
            resp = c.post("/authorize/consent", data={"action": "approve"})
        assert resp.status_code == 400