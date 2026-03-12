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
import pytest
from flask import Flask
from werkzeug.exceptions import HTTPException

from credenza.rest.introspect import introspect_blueprint
from credenza.rest.token import token_blueprint
from credenza.api.auth.client.adapters.adapter import (
    AdapterConfig,
    AdapterInterface,
    AdapterResult,
    AdapterAuthError,
    Subject,
)
from credenza.api.auth.client.client_registry import ClientRegistry, ClientRecord
from credenza.api.common.errors import OAuthError
from credenza.api.common.rate_limit import FixedWindowJitterLimiter
from credenza.api.session.storage.session_store import SessionStore, SessionType


# ---------------------------------------------------------------------------
# Minimal adapter for confidential-client tests
# ---------------------------------------------------------------------------

class _StubAdapter(AdapterInterface):
    ADAPTER_NAME = "stub"
    SUPPORTED_AUTH_METHODS = ("client_secret_basic",)

    def __init__(self, cfg, *, succeed=True):
        self.config = cfg
        self._succeed = succeed

    @classmethod
    def from_dict(cls, config, client_id):
        cfg = AdapterConfig(client_id=client_id, adapter_name=cls.ADAPTER_NAME, config_dict=config)
        return cls(cfg)

    def authenticate(self, proof_context, allowed_methods=None):
        if not self._succeed:
            raise AdapterAuthError("bad credentials", status=401, error_code=OAuthError.UNAUTHORIZED_CLIENT)
        return AdapterResult(subject=Subject(sub="svc1"), auth_context={}, additional_claims={})


def _make_public_client(client_id, *, allowed_introspection_resources=None):
    return ClientRecord(
        client_id=client_id,
        public=True,
        allowed_grant_types=["authorization_code"],
        allowed_resources=["https://rs.example.com"],
        allowed_introspection_resources=list(allowed_introspection_resources or []),
    )


def _make_confidential_client(client_id, *, succeed=True, allowed_introspection_resources=None):
    cfg = AdapterConfig(client_id=client_id, adapter_name="stub", config_dict={})
    adapter = _StubAdapter(cfg, succeed=succeed)
    return ClientRecord(
        client_id=client_id,
        public=False,
        adapter_config=cfg,
        adapter_class=_StubAdapter,
        adapter_instance=adapter,
        allowed_auth_methods=["client_secret_basic"],
        allowed_grant_types=["client_credentials"],
        allowed_resources=["https://rs.example.com"],
        allowed_introspection_resources=list(allowed_introspection_resources or []),
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def store():
    return SessionStore(ttl=2100)


@pytest.fixture
def live_token(store):
    """Create a live user-type session and return its opaque bearer token."""
    now = int(time.time())
    skey, _ = store.create_session(
        session_id=store.generate_session_id(),
        session_type=SessionType.USER,
        access_token=store.generate_session_key(),
        scopes="openid email",
        realm="default",
        userinfo={
            "sub": "user42",
            "email": "user42@example.com",
            "iss": "https://idp.example.com",
        },
        allowed_resources=["https://rs.example.com"],
        expires_at=now + 3600,
        session_ttl=3600,
    )
    return skey


@pytest.fixture
def app(store):
    a = Flask(__name__)
    a.config["SESSION_STORE"] = store
    a.config["CLIENT_REGISTRY"] = ClientRegistry(version="0", clients={})
    a.config["IDP_CLAIM_MAPS"] = {}
    a.config["BASE_URL"] = "https://authn.example.com/authn"
    a.config["ENABLE_LEGACY_API"] = False
    a.register_blueprint(introspect_blueprint)
    a.register_blueprint(token_blueprint)
    a.extensions["rate_limits"] = {
        "10_per_min": FixedWindowJitterLimiter(limit=100, window_sec=60),
        "30_per_min": FixedWindowJitterLimiter(limit=100, window_sec=60),
        "60_per_min": FixedWindowJitterLimiter(limit=100, window_sec=60),
    }
    return a


@pytest.fixture
def client(app):
    return app.test_client()


def _set_registry(app, *client_recs):
    app.config["CLIENT_REGISTRY"] = ClientRegistry(
        version="0",
        clients={cr.client_id: cr for cr in client_recs},
    )


# ---------------------------------------------------------------------------
# Tests: client authentication layer
# ---------------------------------------------------------------------------

def test_introspect_missing_client_id_returns_400(client):
    resp = client.post("/introspect", data={"token": "x"})
    assert resp.status_code == 400


def test_introspect_unknown_client_returns_401(client):
    resp = client.post("/introspect", data={"client_id": "unknown", "token": "x"})
    assert resp.status_code == 401


def test_introspect_confidential_client_bad_creds_returns_401(app, client, live_token):
    _set_registry(app, _make_confidential_client("rs", succeed=False))
    import base64
    creds = base64.b64encode(b"rs:wrongsecret").decode()
    resp = client.post(
        "/introspect",
        data={"token": live_token},
        headers={"Authorization": f"Basic {creds}"},
    )
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Tests: token lookup
# ---------------------------------------------------------------------------

def test_introspect_missing_token_returns_inactive(app, client):
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={"client_id": "rs"})
    assert resp.status_code == 200
    assert resp.get_json()["active"] is False


def test_introspect_empty_token_returns_inactive(app, client):
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={"client_id": "rs", "token": "   "})
    assert resp.status_code == 200
    assert resp.get_json()["active"] is False


def test_introspect_unknown_token_returns_inactive(app, client):
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={"client_id": "rs", "token": "does-not-exist"})
    assert resp.status_code == 200
    assert resp.get_json()["active"] is False


def test_introspect_expired_token_returns_inactive(app, client, store):
    _set_registry(app, _make_public_client("rs"))
    now = int(time.time())
    # Create session with expires_at in the past
    skey, _ = store.create_session(
        session_id=store.generate_session_id(),
        session_type=SessionType.USER,
        access_token=store.generate_session_key(),
        scopes="openid",
        realm="default",
        userinfo={"sub": "u1"},
        allowed_resources=["https://rs.example.com"],
        expires_at=now - 1,
        session_ttl=1,
    )
    resp = client.post("/introspect", data={"client_id": "rs", "token": skey})
    assert resp.status_code == 200
    assert resp.get_json()["active"] is False


# ---------------------------------------------------------------------------
# Tests: active token response
# ---------------------------------------------------------------------------

def test_introspect_active_token_returns_200(app, client, live_token):
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={"client_id": "rs", "token": live_token})
    assert resp.status_code == 200
    assert resp.get_json()["active"] is True


def test_introspect_active_includes_rfc7662_fields(app, client, live_token):
    _set_registry(app, _make_public_client("rs"))
    body = client.post("/introspect", data={"client_id": "rs", "token": live_token}).get_json()
    assert body["active"] is True
    assert body["iss"] == "https://authn.example.com/authn"
    assert body["sub"] == "user42"
    assert "https://rs.example.com" in body["aud"]
    assert "exp" in body
    assert "iat" in body
    assert body["token_type"] == "Bearer"
    assert "scope" in body


def test_introspect_iss_is_credenza_not_idp(app, client, live_token):
    """iss in response must be Credenza's BASE_URL, not the upstream IDP issuer."""
    _set_registry(app, _make_public_client("rs"))
    body = client.post("/introspect", data={"client_id": "rs", "token": live_token}).get_json()
    assert body["iss"] == "https://authn.example.com/authn"
    assert body["iss"] != "https://idp.example.com"


def test_introspect_userinfo_claims_present(app, client, live_token):
    """Userinfo fields from the session are included in the response."""
    _set_registry(app, _make_public_client("rs"))
    body = client.post("/introspect", data={"client_id": "rs", "token": live_token}).get_json()
    assert body["email"] == "user42@example.com"


# ---------------------------------------------------------------------------
# Tests: client introspection gating (Option B)
# ---------------------------------------------------------------------------

def test_introspect_gating_no_intersection_returns_inactive(app, client, live_token):
    """Client with allowed_introspection_resources that don't match the token."""
    _set_registry(app, _make_public_client("rs",
        allowed_introspection_resources=["https://other.example.com"]))
    resp = client.post("/introspect", data={"client_id": "rs", "token": live_token})
    assert resp.get_json()["active"] is False


def test_introspect_gating_with_intersection_allowed(app, client, live_token):
    """Client whose allowed_introspection_resources intersects the token's resources."""
    _set_registry(app, _make_public_client("rs",
        allowed_introspection_resources=["https://rs.example.com"]))
    resp = client.post("/introspect", data={"client_id": "rs", "token": live_token})
    assert resp.get_json()["active"] is True


def test_introspect_gating_empty_means_no_restriction(app, client, live_token):
    """Client with empty allowed_introspection_resources can introspect any token."""
    _set_registry(app, _make_public_client("rs", allowed_introspection_resources=[]))
    resp = client.post("/introspect", data={"client_id": "rs", "token": live_token})
    assert resp.get_json()["active"] is True


# ---------------------------------------------------------------------------
# Tests: resource binding
# ---------------------------------------------------------------------------

def test_introspect_resource_binding_match_allowed(app, client, live_token):
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={
        "client_id": "rs", "token": live_token, "resource": "https://rs.example.com"
    })
    assert resp.get_json()["active"] is True


def test_introspect_resource_binding_no_match_returns_inactive(app, client, live_token):
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={
        "client_id": "rs", "token": live_token, "resource": "https://other.example.com"
    })
    assert resp.get_json()["active"] is False


def test_introspect_no_resource_param_skips_binding(app, client, live_token):
    """Without a resource param, resource binding is not enforced."""
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={"client_id": "rs", "token": live_token})
    assert resp.get_json()["active"] is True


# ---------------------------------------------------------------------------
# Tests: legacy mode
# ---------------------------------------------------------------------------

def test_introspect_legacy_default_resource_matches(app, client, live_token):
    app.config["ENABLE_LEGACY_API"] = True
    app.config["LEGACY_DEFAULT_RESOURCE"] = "https://rs.example.com"
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={"client_id": "rs", "token": live_token})
    assert resp.get_json()["active"] is True


def test_introspect_legacy_default_resource_no_match_returns_inactive(app, client, live_token):
    app.config["ENABLE_LEGACY_API"] = True
    app.config["LEGACY_DEFAULT_RESOURCE"] = "https://other.example.com"
    _set_registry(app, _make_public_client("rs"))
    resp = client.post("/introspect", data={"client_id": "rs", "token": live_token})
    assert resp.get_json()["active"] is False


# ---------------------------------------------------------------------------
# Tests: rate limiting
# ---------------------------------------------------------------------------

def test_introspect_per_client_rate_limit_returns_429(app, client, live_token):
    """Second introspect from the same client within the window is rate-limited."""
    _set_registry(app, _make_public_client("rs"))
    # Disable the IP decorator so only the per-client check inside the handler fires.
    app.config["ENABLE_RATE_LIMITING"] = False
    app.extensions["rate_limits"]["30_per_min"] = FixedWindowJitterLimiter(limit=1, window_sec=60, seed=42)

    client.post("/introspect", data={"client_id": "rs", "token": live_token})  # consumes the token
    r2 = client.post("/introspect", data={"client_id": "rs", "token": live_token})
    assert r2.status_code == 429
    assert r2.get_json()["error"] == "rate_limited"