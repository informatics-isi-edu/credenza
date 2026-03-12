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
from flask import Flask
from credenza.rest.metadata import metadata_blueprint, rfc8414_discovery_url

BASE = "https://authn.example.com/authn"


@pytest.fixture
def app():
    a = Flask(__name__)
    a.config["BASE_URL"] = BASE
    a.register_blueprint(metadata_blueprint)
    return a


@pytest.fixture
def client(app):
    return app.test_client()


def test_metadata_returns_200(client):
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200


def test_metadata_content_type(client):
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.content_type.startswith("application/json")


def test_metadata_cache_control(client):
    resp = client.get("/.well-known/oauth-authorization-server")
    assert "max-age=3600" in resp.headers.get("Cache-Control", "")


def test_metadata_issuer(client):
    body = client.get("/.well-known/oauth-authorization-server").get_json()
    assert body["issuer"] == BASE


def test_metadata_endpoints_derived_from_base_url(client):
    body = client.get("/.well-known/oauth-authorization-server").get_json()
    assert body["authorization_endpoint"] == f"{BASE}/authorize"
    assert body["token_endpoint"] == f"{BASE}/token"
    assert body["device_authorization_endpoint"] == f"{BASE}/device_authorization"
    assert body["introspection_endpoint"] == f"{BASE}/introspect"
    assert body["revocation_endpoint"] == f"{BASE}/revoke"


def test_metadata_base_url_trailing_slash_stripped():
    """BASE_URL with a trailing slash must not produce double-slash endpoints."""
    a = Flask(__name__)
    a.config["BASE_URL"] = BASE + "/"
    a.register_blueprint(metadata_blueprint)
    with a.test_client() as c:
        body = c.get("/.well-known/oauth-authorization-server").get_json()
    assert body["issuer"] == BASE
    assert body["authorization_endpoint"] == f"{BASE}/authorize"


def test_metadata_required_grant_types(client):
    body = client.get("/.well-known/oauth-authorization-server").get_json()
    grants = body["grant_types_supported"]
    assert "authorization_code" in grants
    assert "urn:ietf:params:oauth:grant-type:device_code" in grants
    assert "urn:ietf:params:oauth:grant-type:token-exchange" in grants


def test_metadata_pkce_s256_only(client):
    body = client.get("/.well-known/oauth-authorization-server").get_json()
    assert body["code_challenge_methods_supported"] == ["S256"]


def test_metadata_response_types(client):
    body = client.get("/.well-known/oauth-authorization-server").get_json()
    assert body["response_types_supported"] == ["code"]


def test_metadata_resource_indicators(client):
    body = client.get("/.well-known/oauth-authorization-server").get_json()
    assert body["resource_indicators_supported"] is True


def test_metadata_revocation_endpoint_auth_methods(client):
    body = client.get("/.well-known/oauth-authorization-server").get_json()
    methods = body["revocation_endpoint_auth_methods_supported"]
    assert "client_secret_basic" in methods
    assert "client_secret_post" in methods
    assert "none" in methods


# ---------------------------------------------------------------------------
# Tests: RFC 8414 Section 2 discovery URL construction
# ---------------------------------------------------------------------------

def test_rfc8414_discovery_url_with_path():
    """Issuer with path prefix: well-known path appended after the segment."""
    url = rfc8414_discovery_url("https://authn.example.com/authn")
    assert url == "https://authn.example.com/.well-known/oauth-authorization-server/authn"


def test_rfc8414_discovery_url_no_path():
    """Issuer with no path: standard well-known URL with no suffix."""
    url = rfc8414_discovery_url("https://authn.example.com")
    assert url == "https://authn.example.com/.well-known/oauth-authorization-server"


def test_rfc8414_discovery_url_trailing_slash_stripped():
    url = rfc8414_discovery_url("https://authn.example.com/authn/")
    assert url == "https://authn.example.com/.well-known/oauth-authorization-server/authn"


def test_rfc8414_discovery_url_nested_path():
    url = rfc8414_discovery_url("https://host/a/b")
    assert url == "https://host/.well-known/oauth-authorization-server/a/b"