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
from requests import HTTPError
from credenza.api.oidc_client import OIDCClientFactory, OIDCClient

#
# Helper stub for requests responses
#
class DummyResponse:
    def __init__(self, status_code=200, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise HTTPError(f"{self.status_code} Error")

    def json(self):
        return self._json_data

#
# Factory: unknown realm -> ValueError
#
def test_factory_get_client_unknown_realm():
    factory = OIDCClientFactory({"realm1": {"client_secret_file": __file__}})
    with pytest.raises(ValueError) as exc:
        factory.get_client("nonexistent")
    assert "Unknown realm" in str(exc.value)

#
# _load_client_secret: missing file -> ValueError
#
def test_load_client_secret_file_missing(tmp_path, dummy_profile):
    missing = tmp_path / "does_not_exist.json"
    dummy_profile["client_secret_file"] = missing
    with pytest.raises(ValueError) as exc:
        OIDCClient(dummy_profile)
    assert "Client secret file does not exist" in str(exc.value)

#
# _fetch_discovery_metadata: non-200 -> HTTPError
#
def test_fetch_discovery_metadata_http_error(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda url: DummyResponse(status_code=404))
    with pytest.raises(HTTPError):
        OIDCClient._fetch_discovery_metadata("https://example.com/.well-known/openid-configuration")

#
# _jwks_expired logic
#
def test_jwks_expired_true_if_never_fetched(tmp_path, dummy_profile):
    # Create a minimal client‐secret JSON so __init__ succeeds
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id": "cid", "client_secret": "cs"}))
    dummy_profile["client_secret_file"] = secret

    client = OIDCClient(dummy_profile)

    # Never fetched -> expired
    client._jwks_fetched_at = None
    assert client._jwks_expired()


def test_jwks_expired_false_within_ttl(monkeypatch, dummy_profile, tmp_path):
    # Same setup for client‐secret
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id": "cid", "client_secret": "cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    # Simulate a fetch just 100s ago, with TTL=200 -> not expired
    now = time.time()
    monkeypatch.setattr(time, "time", lambda: now)
    client._jwks_fetched_at = now - 100
    assert not client._jwks_expired(ttl=200)

#
# _load_jwks: missing jwks_uri -> ValueError
#
def test_load_jwks_missing_uri(dummy_profile, tmp_path):
    # create a dummy secret file so __init__ passes
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    with pytest.raises(ValueError) as exc:
        client._load_jwks()
    assert "JWKs URI not configured" in str(exc.value)

#
# _load_jwks: valid URI -> populates .jwks
#
def test_load_jwks_success(monkeypatch, dummy_profile, tmp_path):
    # secret file
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    # stub requests.get for JWKS
    jwk_set = {"keys":[{"kty":"oct","k":"Zm9v"}]}
    monkeypatch.setattr(requests, "get", lambda uri: DummyResponse(200, jwk_set))

    dummy_profile["client_secret_file"] = secret
    dummy_profile["jwks_uri"] = "https://issuer/jwks"
    client = OIDCClient(dummy_profile)

    # force reload
    client.jwks = None
    client._jwks_fetched_at = None

    client._load_jwks()
    # JsonWebKey.import_key_set created a jwks object with .keys
    assert hasattr(client.jwks, "keys")

#
# exchange_code_for_tokens: underlying fetch_token raises -> propagates
#
def test_exchange_code_for_tokens_failure(monkeypatch, dummy_profile, tmp_path):
    # secret file
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    # stub fetch_token to throw
    dummy = type("D", (), {})()
    dummy.fetch_token = lambda **kw: (_ for _ in ()).throw(Exception("bad"))
    monkeypatch.setattr(client, "get_oauth_session", lambda *args, **kw: dummy)

    with pytest.raises(Exception):
        client.exchange_code_for_tokens("code", "redir")

#
# fetch_dependent_tokens: underlying fetch_token raises -> propagates
#
def test_fetch_dependent_tokens_failure(monkeypatch, dummy_profile, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    dummy = type("D", (), {})()
    dummy.fetch_token = lambda **kw: (_ for _ in ()).throw(Exception("fail"))
    monkeypatch.setattr(client, "get_oauth_session", lambda *args, **kw: dummy)

    with pytest.raises(Exception):
        client.fetch_dependent_tokens("at", "grant", scope=None, access_type=None)

#
# refresh_access_token: underlying refresh_token raises -> propagates
#
def test_refresh_access_token_failure(monkeypatch, dummy_profile,tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    dummy = type("D", (), {})()
    dummy.refresh_token = lambda **kw: (_ for _ in ()).throw(Exception("oops"))
    monkeypatch.setattr(client, "get_oauth_session", lambda token=None: dummy)

    with pytest.raises(Exception):
        client.refresh_access_token("rt")

#
# fetch_userinfo: non-200 -> propagates
#
def test_fetch_userinfo_failure(monkeypatch, dummy_profile, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    dummy_profile["userinfo_url"] = "https://issuer/userinfo"
    client = OIDCClient(dummy_profile)

    monkeypatch.setattr(requests, "get", lambda url, headers: DummyResponse(500))
    with pytest.raises(Exception):
        client.fetch_userinfo("token")

#
# introspect_token: no introspect_url -> NotImplementedError
#
def test_introspect_token_not_configured(dummy_profile, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    del dummy_profile["introspect_url"]
    client = OIDCClient(dummy_profile)

    with pytest.raises(NotImplementedError):
        client.introspect_token("token")

#
# validate_access_token: introspection error -> ValueError
#
def test_validate_access_token_introspection_failure(monkeypatch, dummy_profile, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    # make introspect_token raise
    monkeypatch.setattr(client, "introspect_token", lambda *args, **kw: (_ for _ in ()).throw(Exception("fail")))
    with pytest.raises(ValueError) as exc:
        client.validate_access_token("token")
    assert "Token introspection failed" in str(exc.value)

#
# validate_access_token: inactive token -> ValueError
#
def test_validate_access_token_inactive(monkeypatch, dummy_profile, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    monkeypatch.setattr(client, "introspect_token", lambda *args, **kw: {"active": False})
    with pytest.raises(ValueError) as exc:
        client.validate_access_token("token")
    assert "Inactive or expired access token" in str(exc.value)

#
# validate_access_token: expired exp -> ValueError
#
def test_validate_access_token_expired(monkeypatch, dummy_profile, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    now = int(time.time())
    claims = {"active": True, "exp": now - 1, "iat": now - 10, "aud": client.client_id, "iss": client.issuer}
    monkeypatch.setattr(client, "introspect_token", lambda *args, **kw: claims)
    with pytest.raises(ValueError) as exc:
        client.validate_access_token("token")
    assert "Access token expired" in str(exc.value)

#
# validate_access_token: not-yet-valid nbf -> ValueError
#
def test_validate_access_token_not_yet_valid(monkeypatch, dummy_profile, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    now = int(time.time())
    claims = {"active": True, "exp": now + 100, "iat": now + 10, "nbf": now + 10, "aud": client.client_id, "iss": client.issuer}
    monkeypatch.setattr(client, "introspect_token", lambda *args, **kw: claims)
    with pytest.raises(ValueError) as exc:
        client.validate_access_token("token")
    assert "Access token not yet valid" in str(exc.value)

#
# validate_access_token: audience mismatch -> ValueError
#
def test_validate_access_token_audience_mismatch(monkeypatch, dummy_profile, tmp_path):
    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    now = int(time.time())
    claims = {"active": True, "exp": now + 100, "iat": now - 10, "aud": "other", "iss": client.issuer}
    monkeypatch.setattr(client, "introspect_token", lambda *args, **kw: claims)
    with pytest.raises(ValueError) as exc:
        client.validate_access_token("token", required_audience=client.client_id)
    assert "Access token audience mismatch" in str(exc.value)

#
# validate_access_token: issuer mismatch -> ValueError
#
def test_validate_access_token_issuer_mismatch(monkeypatch, dummy_profile, tmp_path):
    # monkeypatch discovery to set issuer A
    jwks_meta = dummy_profile
    jwks_meta["issuer"] = "https://issuerA"
    monkeypatch.setattr(requests, "get", lambda url: DummyResponse(200, jwks_meta))

    secret = tmp_path / "secret.json"
    secret.write_text(json.dumps({"client_id":"cid","client_secret":"cs"}))

    dummy_profile["client_secret_file"] = secret
    client = OIDCClient(dummy_profile)

    now = int(time.time())
    claims = {"active": True, "exp": now + 100, "iat": now - 10, "aud": client.client_id, "iss": "https://issuerB"}
    monkeypatch.setattr(client, "introspect_token", lambda *args, **kw: claims)

    with pytest.raises(ValueError) as exc:
        client.validate_access_token("token", required_audience=client.client_id)
    assert "Issuer mismatch" in str(exc.value)
