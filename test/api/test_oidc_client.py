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
import json
import time
import pytest
import requests
from types import SimpleNamespace
from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import jwt, JsonWebKey
from credenza.api.oidc_client import OIDCClientFactory, OIDCClient

# Shared profile fixtures
@pytest.fixture
def profile_file(tmp_path, monkeypatch):
    # Create a temporary client secret file
    data = {"client_id": "cid", "client_secret": "csecret"}
    file = tmp_path / "secret.json"
    file.write_text(json.dumps(data))
    monkeypatch.setenv("FLASK_ENV", "testing")
    return str(file)

@pytest.fixture
def discovery_metadata(discovery_response, monkeypatch):
    meta = discovery_response
    # Mock requests.get for discovery
    def fake_get(url, *args, **kwargs):
        if url.endswith(".well-known/openid-configuration"):
            resp = SimpleNamespace()
            resp.status_code = 200
            resp.json = lambda: meta
            resp.raise_for_status = lambda: None
            return resp
        elif url == meta["jwks_uri"]:
            jwk_set = {"keys": [{"kty": "oct", "kid": "1", "k": "abc", "alg": "HS256"}]}
            resp = SimpleNamespace()
            resp.status_code = 200
            resp.json = lambda: jwk_set
            resp.raise_for_status = lambda: None
            return resp
        else:
            raise ValueError("Unexpected URL")
    monkeypatch.setattr(requests, "get", fake_get)
    return meta

# Factory tests
def test_factory_unknown_realm(profile_file):
    factory = OIDCClientFactory({})
    with pytest.raises(ValueError):
        factory.get_client("unknown")

def test_factory_caches_client(profile_file, discovery_metadata, monkeypatch):
    profile = {"client_secret_file": profile_file, "discovery_url": "https://iss/.well-known/openid-configuration"}
    factory = OIDCClientFactory({"r1": profile})
    c1 = factory.get_client("r1")
    c2 = factory.get_client("r1")
    assert c1 is c2

# OIDCClient tests
@pytest.fixture
def client(discovery_metadata, profile_file):
    profile = {"client_secret_file": profile_file, "discovery_url": "https://iss/.well-known/openid-configuration"}
    return OIDCClient(profile)

def test_client_loads_secret(client):
    assert client.client_id == "cid"
    assert client.client_secret == "csecret"
    assert client.authorize_url.endswith("/auth")
    assert client.token_url.endswith("/token")

def test_jwks_load_and_expiry(client, monkeypatch):
    client._jwks_fetched_at = time.time() - 100000
    client._load_jwks()
    assert client.jwks.keys
    assert not client._jwks_expired(ttl=3600)


# Mock underlying OAuth2Session for token exchange
class DummySession:
    def __init__(self, status_code=200, exc=None):
        self._status = status_code
        self._exc = exc

    def revoke_token(self, url, token, token_type_hint):
        if self._exc:
            raise self._exc
        return SimpleNamespace(status_code=self._status)

    def fetch_token(self, url, **kwargs):
        return {"access_token": "at", "refresh_token": "rt", "id_token": "itok"}
    def refresh_token(self, url, **kwargs):
        return {"access_token": "at2", "expires_in": 3600}


@pytest.fixture(autouse=True)
def patch_oauth(request, monkeypatch):
    if request.node.get_closest_marker("skip_oauth_patch"):
        return
    monkeypatch.setattr(OIDCClient, "get_oauth_session", lambda self, **kw: DummySession())

@pytest.mark.skip_oauth_patch
def test_get_oauth_session(client):
    o1 = client.get_oauth_session()
    assert isinstance(o1, OAuth2Session)

def test_exchange_and_refresh(client):
    tok = client.exchange_code_for_tokens("code", "https://cb", "state")
    assert tok["access_token"] == "at"
    # Test dependent token fetch
    token = client.fetch_dependent_tokens("at", grant_type="urn:ietf:params:oauth:grant-type:token-exchange")
    assert token["access_token"] == "at"
    # Refresh access token
    new_tok = client.refresh_access_token("rtok")
    assert new_tok["access_token"] == "at2"

def test_fetch_userinfo(client, monkeypatch):
    # Mock requests.get for userinfo
    resp = SimpleNamespace(status_code=200, json=lambda: {"sub": "u1"}, raise_for_status=lambda: None)
    monkeypatch.setattr(requests, "get", lambda url, headers: resp)
    ui = client.fetch_userinfo("tk")
    assert ui["sub"] == "u1"

class DummyClaims(dict):
    def validate(self, leeway=120):
        # no-op
        return None

def test_validate_id_token(client, monkeypatch):
    monkeypatch.setattr(client, "_load_jwks", lambda: None)
    # Patch jwt.decode to return a DummyClaims
    claims_data = {
        "sub": "u",
        "iss": client.issuer,
        "aud": [client.client_id],
        "exp": time.time() + 10,
        "iat": time.time(),
    }
    monkeypatch.setattr(
        jwt, "decode",
        lambda token, key, claims_options: DummyClaims(claims_data)
    )

    result = client.validate_id_token("token")
    assert result["sub"] == "u"

def test_introspect_and_validate_access_token(client, monkeypatch):
    # Setup introspection endpoint
    client.introspect_url = "https://iss/introspect"
    # Mock requests.post
    valid = {"active": True, "exp": time.time()+100, "iat": time.time()-100, "iss": client.issuer, "aud": [client.client_id]}
    resp = SimpleNamespace(status_code=200, json=lambda: valid, raise_for_status=lambda: None)
    monkeypatch.setattr(requests, "post", lambda url, data, auth: resp)
    # Test introspect_token
    result = client.introspect_token("at")
    assert result["active"]
    # Test validate_access_token happy path
    claims = client.validate_access_token("at", required_audience=client.client_id)
    assert claims["active"]

# Error conditions
def test_validate_access_token_inactive(client, monkeypatch):
    client.introspect_url = "https://iss/introspect"
    resp = SimpleNamespace(status_code=200, json=lambda: {"active": False}, raise_for_status=lambda: None)
    monkeypatch.setattr(requests, "post", lambda url, data, auth: resp)
    with pytest.raises(ValueError):
        client.validate_access_token("at")

def test_introspect_not_configured(client):
    client.introspect_url = None
    with pytest.raises(NotImplementedError):
        client.introspect_token("at")

def test_validate_access_token_not_configured(client):
    client.introspect_url = None
    with pytest.raises(NotImplementedError):
        client.validate_access_token("at")


def test_manual_endpoints(monkeypatch, dummy_profile, profile_file):
    # Test client with manual profiles
    dummy_profile["client_secret_file"] = profile_file

    oc = OIDCClient(dummy_profile)

    assert oc.authorize_url == "https://issuer/auth"
    assert oc.introspect_url == "https://issuer/instrospect"
    assert oc.revocation_url == "https://issuer/token/revoke"


def test_revoke_token_success(monkeypatch, client):
    # stub out get_oauth_session -> returns DummySession(200)
    monkeypatch.setattr(client, "get_oauth_session", lambda: DummySession(status_code=200))
    assert client.revoke_token("openid", "tok", token_type_hint="access_token") is True


def test_revoke_token_http_failure(monkeypatch, client):
    # status != 200 -> False
    monkeypatch.setattr(client, "get_oauth_session", lambda: DummySession(status_code=400))
    assert client.revoke_token("openid", "tok", token_type_hint="refresh_token") is False


def test_revoke_token_exception(monkeypatch, client):
    # network or other exception -> False
    err = RuntimeError("boom")
    monkeypatch.setattr(client, "get_oauth_session", lambda: DummySession(exc=err))
    assert client.revoke_token("openid", "tok") is False
