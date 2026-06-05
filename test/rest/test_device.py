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
from unittest.mock import Mock
from flask import g
from urllib.parse import urlparse, parse_qs
from credenza.rest import device as df
from credenza.api.session.storage.session_store import SessionData, SessionType
from credenza.rest.device import device_callback
from credenza.api.auth.client.client_registry import ClientRegistry, ClientRecord
from credenza.api.common.rate_limit import FixedWindowJitterLimiter
from credenza.rest.helpers import GrantType

class StubDeviceClient:
    def __init__(self, *, tokens=None, userinfo=None, scope="openid email profile",
                 userinfo_endpoint_data=None, userinfo_endpoint_exc=None):
        self.scope = scope
        self._tokens = tokens or {}
        self._userinfo = userinfo or {}
        self._userinfo_endpoint_data = userinfo_endpoint_data
        self._userinfo_endpoint_exc = userinfo_endpoint_exc
        self.userinfo_fetch_calls = []

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

    def fetch_userinfo(self, access_token):
        self.userinfo_fetch_calls.append(access_token)
        if self._userinfo_endpoint_exc is not None:
            raise self._userinfo_endpoint_exc
        return self._userinfo_endpoint_data or {}

def _make_device_registry(client_id="device-test-client", *,
                          public=True,
                          allowed_resources=None,
                          allowed_scopes=None,
                          allowed_grant_types=None):
    """Build a minimal ClientRegistry with one device client for testing."""
    cr = ClientRecord(
        client_id=client_id,
        public=public,
        allowed_grant_types=allowed_grant_types or ["urn:ietf:params:oauth:grant-type:device_code"],
        allowed_resources=allowed_resources or ["urn:test:resource"],
        allowed_scopes=allowed_scopes or ["openid", "email", "profile"],
    )
    return ClientRegistry(version="1", clients={client_id: cr})


@pytest.fixture
def client(app, store, monkeypatch):
    """Register the device blueprint and return a test client (no registry -- legacy mode)."""
    app.register_blueprint(df.device_blueprint)
    app.testing = True
    return app.test_client()


@pytest.fixture
def client_with_registry(app, store, monkeypatch):
    """Register the device blueprint with a client registry configured (Phase 3 compliance mode)."""
    app.config["CLIENT_REGISTRY"] = _make_device_registry()
    app.register_blueprint(df.device_blueprint)
    app.testing = True
    return app.test_client()

def test_start_device_flow_defaults(client, app, store, frozen_time):
    resp = client.post("/device/start")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "device_code" in data and len(data["device_code"]) == 32  # 128-bit hex
    assert all(c in "0123456789abcdef" for c in data["device_code"])
    assert "user_code" in data and len(data["user_code"]) == 8  # 32-bit hex uppercase
    assert all(c in "0123456789ABCDEF" for c in data["user_code"])
    assert data["interval"] == 3
    assert data["expires_in"] == df.DEVICE_FLOW_TTL
    assert data["verification_uri"].endswith(f"/device/verify/{data['user_code']}")
    flow = store.get_device_flow(data["device_code"])
    assert flow["user_code"] == data["user_code"]
    assert flow["realm"] == app.config["DEFAULT_REALM"]
    assert flow["issued_at"] == frozen_time
    assert flow["expires_at"] == frozen_time + df.DEVICE_FLOW_TTL
    assert store.consume_usercode_mapping(data["user_code"]) == data["device_code"]

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
    assert resp.status_code == 410  # Gone - flow expired
    assert "expired" in resp.get_json()["message"].lower()

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

    provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
    monkeypatch.setattr(provider, "process_additional_tokens", lambda t, now: {})
    monkeypatch.setattr(provider, "enrich_userinfo", lambda ui, ext: None)

    resp = client.get("/device/callback", query_string={"code":"c","state":state})
    assert resp.status_code == 200
    assert b"Device Authorized" in resp.data

    new_flow = store.get_device_flow(device_code)
    assert new_flow["verified"] is True
    skey = new_flow["session_key"]
    sid, session = store.get_session_by_session_key(skey)
    assert isinstance(session, SessionData)
    assert session.access_token == "acc"


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
    monkeypatch.setattr("credenza.rest.device.augment_session", mock_augment)

    update_mock = Mock()
    monkeypatch.setattr(store, "update_session", update_mock)

    with app.test_request_context(f"/device/callback?code=abc&state={device_code}"):
        g.session_key = session_key
        resp = device_callback()

    assert "Device Authorized" in resp
    assert call_count["count"] == 2
    update_mock.assert_called_once()
    updated_sid, updated_session = update_mock.call_args[0]
    assert updated_sid == session_id
    assert updated_session.userinfo == dummy_augmented_userinfo
    assert updated_session.additional_tokens == dummy_additional_tokens


# ---------------------------------------------------------------------------
# RFC 8628 compliance tests (client_id enforcement, grant type
# validation, scope/resource validation)
# ---------------------------------------------------------------------------

def test_device_authorization_missing_client_id(client_with_registry):
    resp = client_with_registry.post("/device_authorization")
    assert resp.status_code == 400

def test_device_authorization_unknown_client(client_with_registry):
    resp = client_with_registry.post("/device_authorization",
                                     data={"client_id": "no-such-client"})
    assert resp.status_code == 401

def test_device_authorization_wrong_grant_type(app, store):
    """Client exists but does not have device_code in allowed_grant_types."""
    wrong_registry = _make_device_registry(
        allowed_grant_types=["authorization_code"]
    )
    app.config["CLIENT_REGISTRY"] = wrong_registry
    app.register_blueprint(df.device_blueprint)
    c = app.test_client()
    resp = c.post("/device_authorization",
                  data={"client_id": "device-test-client"})
    assert resp.status_code == 401

def test_device_authorization_scope_denied(client_with_registry):
    resp = client_with_registry.post("/device_authorization",
                                     data={"client_id": "device-test-client",
                                           "scope": "openid bad_scope"})
    assert resp.status_code == 400

def test_device_authorization_resource_denied(client_with_registry):
    resp = client_with_registry.post("/device_authorization",
                                     data={"client_id": "device-test-client",
                                           "resource": "not:allowed"})
    assert resp.status_code == 400

def test_device_authorization_valid_client_stores_client_id(client_with_registry, app, store, frozen_time):
    resp = client_with_registry.post("/device_authorization",
                                     data={"client_id": "device-test-client"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "device_code" in data
    flow = store.get_device_flow(data["device_code"])
    assert flow["client_id"] == "device-test-client"

def test_device_authorization_valid_client_with_resource(client_with_registry, app, store, frozen_time):
    resp = client_with_registry.post("/device_authorization",
                                     data={"client_id": "device-test-client",
                                           "resource": "urn:test:resource"})
    assert resp.status_code == 200
    data = resp.get_json()
    flow = store.get_device_flow(data["device_code"])
    assert flow["allowed_resources"] == ["urn:test:resource"]

def test_device_authorization_valid_client_with_scope(client_with_registry, app, store, frozen_time):
    resp = client_with_registry.post("/device_authorization",
                                     data={"client_id": "device-test-client",
                                           "scope": "openid email"})
    assert resp.status_code == 200

def test_device_authorization_legacy_start_also_accepts_client_id(client_with_registry, app, store, frozen_time):
    """The /device/start alias should also accept client_id when registry is configured."""
    resp = client_with_registry.post("/device/start",
                                     data={"client_id": "device-test-client"})
    assert resp.status_code == 200
    data = resp.get_json()
    flow = store.get_device_flow(data["device_code"])
    assert flow["client_id"] == "device-test-client"


def test_device_authorization_unregistered_client_rejected_by_default(app, store):
    """Unknown client_id is rejected when DEVICE_ALLOW_UNREGISTERED_CLIENTS is not set."""
    app.config["CLIENT_REGISTRY"] = _make_device_registry()
    app.register_blueprint(df.device_blueprint)
    resp = app.test_client().post("/device_authorization",
                                  data={"client_id": "nobody"})
    assert resp.status_code == 401


def test_device_authorization_unregistered_client_allowed_when_configured(app, store, frozen_time):
    """Unknown client_id is accepted when DEVICE_ALLOW_UNREGISTERED_CLIENTS=True."""
    app.config["CLIENT_REGISTRY"] = _make_device_registry()
    app.config["ALLOW_UNREGISTERED_CLIENTS"] = True
    app.register_blueprint(df.device_blueprint)
    resp = app.test_client().post("/device_authorization",
                                  data={"client_id": "unknown-client"})
    assert resp.status_code == 200
    data = resp.get_json()
    flow = store.get_device_flow(data["device_code"])
    assert flow["client_id"] == "unknown-client"


# ---------------------------------------------------------------------------
# IP rate limit tests for device endpoints
# ---------------------------------------------------------------------------

def test_start_device_flow_ip_rate_limit_returns_429(app, store):
    """Second POST to /device/start from the same IP within the window is rate-limited."""
    app.register_blueprint(df.device_blueprint)
    app.extensions["rate_limits"]["30_per_min"] = FixedWindowJitterLimiter(limit=1, window_sec=60, seed=42)

    with app.test_client() as c:
        c.post("/device/start")  # consumes the IP token
        r2 = c.post("/device/start")
    assert r2.status_code == 429
    assert r2.get_json()["error"] == "rate_limited"


def test_verify_device_ip_rate_limit_returns_429(app, store):
    """Second GET to /device/verify from the same IP within the window is rate-limited."""
    app.register_blueprint(df.device_blueprint)
    app.extensions["rate_limits"]["30_per_min"] = FixedWindowJitterLimiter(limit=1, window_sec=60, seed=42)

    with app.test_client() as c:
        c.get("/device/verify/BADCODE1")  # consumes the IP token (returns 404, but limit is consumed)
        r2 = c.get("/device/verify/BADCODE2")
    assert r2.status_code == 429
    assert r2.get_json()["error"] == "rate_limited"


# ---------------------------------------------------------------------------
# Userinfo endpoint fallback tests for device_callback
# ---------------------------------------------------------------------------

def _setup_fallback_device_flow(app, store, stub, monkeypatch, device_code="DCFALL"):
    """Store a ready device flow and wire up the stub OIDC client and augmentation."""
    store.set_device_flow(device_code, {
        "realm": app.config["DEFAULT_REALM"],
        "redirect_uri": f"{app.config['BASE_URL']}/device/callback",
        "nonce": "N999",
        "code_verifier": "CVFALL",
        "refresh": False,
    }, ttl=60)
    monkeypatch.setattr(app.config["OIDC_CLIENT_FACTORY"], "get_client",
                        lambda realm, native_client=True: stub)
    provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
    monkeypatch.setattr(provider, "process_additional_tokens", lambda t, now: {})
    monkeypatch.setattr(provider, "enrich_userinfo", lambda ui, ext: None)
    return device_code


def test_device_callback_acr_rejection(client, app, store, monkeypatch):
    # IDP profile requires aal/2 and ial/2; ID token only asserts aal/1 -- login must be rejected.
    app.config["OIDC_IDP_PROFILES"]["test"] = {
        "required_acr": ["https://example.com/aal/2", "https://example.com/ial/2"]
    }
    try:
        stub = StubDeviceClient(
            tokens={"id_token": "id", "access_token": "acc", "refresh_token": "rt",
                    "scope": "openid", "refresh_expires_in": 0},
            userinfo={"sub": "u1", "acr": "https://example.com/aal/1"},
        )
        device_code = _setup_fallback_device_flow(app, store, stub, monkeypatch, device_code="DCACR")
        resp = client.get("/device/callback", query_string={"code": "c", "state": device_code})
        assert resp.status_code == 403
        assert store.get_device_flow(device_code).get("session_key") is None
    finally:
        app.config["OIDC_IDP_PROFILES"].pop("test", None)


def test_device_callback_acr_passes_when_satisfied(client, app, store, monkeypatch):
    # All required ACR URIs present -- login succeeds.
    app.config["OIDC_IDP_PROFILES"]["test"] = {
        "required_acr": ["https://example.com/aal/2", "https://example.com/ial/2"]
    }
    try:
        stub = StubDeviceClient(
            tokens={"id_token": "id", "access_token": "acc", "refresh_token": "rt",
                    "scope": "openid", "refresh_expires_in": 0},
            userinfo={"sub": "u1", "acr": "https://example.com/aal/2 https://example.com/ial/2"},
        )
        device_code = _setup_fallback_device_flow(app, store, stub, monkeypatch, device_code="DCACRPASS")
        resp = client.get("/device/callback", query_string={"code": "c", "state": device_code})
        assert resp.status_code == 200
    finally:
        app.config["OIDC_IDP_PROFILES"].pop("test", None)


def test_device_callback_userinfo_fallback_fills_missing_claims(client, app, store, monkeypatch):
    # IDP profile requests email+profile; ID token is sparse; endpoint fills claims.
    app.config["OIDC_IDP_PROFILES"]["test"] = {"scopes": "openid email profile"}
    try:
        stub = StubDeviceClient(
            tokens={"id_token": "id", "access_token": "acc", "refresh_token": "rt",
                    "scope": "openid email profile", "refresh_expires_in": 0},
            userinfo={"sub": "u1"},
            userinfo_endpoint_data={"email": "u1@example.com", "name": "User One"},
        )
        device_code = _setup_fallback_device_flow(app, store, stub, monkeypatch)
        resp = client.get("/device/callback", query_string={"code": "c", "state": device_code})
        assert resp.status_code == 200
        flow = store.get_device_flow(device_code)
        _, session = store.get_session_by_session_key(flow["session_key"])
        assert session.userinfo["email"] == "u1@example.com"
        assert session.userinfo["name"] == "User One"
        assert stub.userinfo_fetch_calls == ["acc"]
    finally:
        app.config["OIDC_IDP_PROFILES"].pop("test", None)


def test_device_callback_userinfo_fallback_not_called_when_claims_present(client, app, store, monkeypatch):
    # ID token already carries email and name -- endpoint must not be called.
    app.config["OIDC_IDP_PROFILES"]["test"] = {"scopes": "openid email profile"}
    try:
        stub = StubDeviceClient(
            tokens={"id_token": "id", "access_token": "acc", "refresh_token": "rt",
                    "scope": "openid email profile", "refresh_expires_in": 0},
            userinfo={"sub": "u1", "email": "u1@example.com", "name": "User One",
                      "preferred_username": "u1"},
        )
        device_code = _setup_fallback_device_flow(app, store, stub, monkeypatch)
        resp = client.get("/device/callback", query_string={"code": "c", "state": device_code})
        assert resp.status_code == 200
        assert stub.userinfo_fetch_calls == []
    finally:
        app.config["OIDC_IDP_PROFILES"].pop("test", None)


def test_device_callback_userinfo_fallback_not_called_with_skip_flag(client, app, store, monkeypatch):
    # skip_userinfo_fallback: true suppresses the call even when claims are missing.
    app.config["OIDC_IDP_PROFILES"]["test"] = {
        "scopes": "openid email profile",
        "skip_userinfo_fallback": True,
    }
    try:
        stub = StubDeviceClient(
            tokens={"id_token": "id", "access_token": "acc", "refresh_token": "rt",
                    "scope": "openid email profile", "refresh_expires_in": 0},
            userinfo={"sub": "u1"},
        )
        device_code = _setup_fallback_device_flow(app, store, stub, monkeypatch)
        resp = client.get("/device/callback", query_string={"code": "c", "state": device_code})
        assert resp.status_code == 200
        assert stub.userinfo_fetch_calls == []
    finally:
        app.config["OIDC_IDP_PROFILES"].pop("test", None)


def test_device_callback_userinfo_fallback_failure_creates_degraded_session(client, app, store, monkeypatch):
    # Endpoint raises; callback still succeeds and session is created without the missing claims.
    app.config["OIDC_IDP_PROFILES"]["test"] = {"scopes": "openid email profile"}
    try:
        stub = StubDeviceClient(
            tokens={"id_token": "id", "access_token": "acc", "refresh_token": "rt",
                    "scope": "openid email profile", "refresh_expires_in": 0},
            userinfo={"sub": "u1"},
            userinfo_endpoint_exc=RuntimeError("network error"),
        )
        device_code = _setup_fallback_device_flow(app, store, stub, monkeypatch)
        resp = client.get("/device/callback", query_string={"code": "c", "state": device_code})
        assert resp.status_code == 200
        flow = store.get_device_flow(device_code)
        _, session = store.get_session_by_session_key(flow["session_key"])
        assert session is not None
        assert session.userinfo.get("email") is None
        assert stub.userinfo_fetch_calls == ["acc"]
    finally:
        app.config["OIDC_IDP_PROFILES"].pop("test", None)
