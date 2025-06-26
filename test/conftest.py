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
import sys, pathlib
from flask import Flask, jsonify
from werkzeug.utils import import_string
from werkzeug.exceptions import HTTPException

# Insert the project root (one level up from tests/) onto sys.path
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from credenza.rest import session as sm
from credenza.api.util import AESGCMCodec
from credenza.api.session.storage.session_store import SessionStore, SessionData, SessionMetadata
from credenza.api.oidc_client import OIDCClientFactory, OIDCClient

COOKIE_NAME = "credenza-test"

@pytest.fixture(scope="function")
def store():
    return SessionStore(ttl=2100)

@pytest.fixture()
def discovery_response():
    return {
        "authorization_endpoint": "https://issuer/auth",
        "token_endpoint": "https://issuer/token",
        "userinfo_endpoint": "https://issuer/userinfo",
        "revocation_endpoint": "https://issuer/token/revoke",
        "jwks_uri": "https://issuer/jwks",
        "issuer": "https://issuer/"
}

@pytest.fixture()
def dummy_profile():
    return {
        "client_secret_file": "/path/does/not/matter",
        "authorize_url": "https://issuer/auth",
        "introspect_url": "https://issuer/instrospect",
        "token_url": "https://issuer/token",
        "userinfo_url": "https://issuer/userinfo",
        "revocation_url": "https://issuer/token/revoke",
        "redirect_uri": "https://client/callback",
        "scopes": "openid email profile",
}

@pytest.fixture
def app(store, discovery_response, dummy_profile, monkeypatch):
    app = Flask(__name__)
    app.config["DEFAULT_REALM"] = "test"
    app.config["SESSION_STORE"] = store
    app.config["COOKIE_NAME"] = COOKIE_NAME
    app.config["CRYPTO_CODEC"] = AESGCMCodec(key="supersecretvalue")
    app.config["OIDC_CLIENT_FACTORY"] = OIDCClientFactory({"test": dummy_profile})
    app.config["OIDC_IDP_PROFILES"] = {
        "default": {"logout_url": "https://idp/logout"}
    }
    app.config["ENABLE_LEGACY_API"] = False
    app.config["BASE_URL"] = "https://localhost"
    app.config["SERVER_NAME"] = "localhost"
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = \
        {"default":
             import_string("credenza.api.session.augmentation.base_provider:DefaultSessionAugmentationProvider")(),
         "globus":
             import_string("credenza.api.session.augmentation.globus_provider:GlobusSessionAugmentationProvider")()}

    app.config["REFRESH_WORKER_POLL_INTERVAL"] = 60
    app.config["SESSION_EXPIRY_THRESHOLD"] = 300
    app.config["TOKEN_EXPIRY_THRESHOLD"] = 300

    # Prevent any real HTTP on discovery
    monkeypatch.setattr(
        OIDCClient,
        "_fetch_discovery_metadata",
        staticmethod(lambda url: discovery_response),
        raising=True
    )

    # Stub OIDCClient client secret loading to avoid file I/O
    monkeypatch.setattr(
        OIDCClient,
        "_load_client_secret",
        lambda self: setattr(self, "client_id", "cid") or setattr(self, "client_secret", "secret")
    )

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        response = e.get_response()
        response.data = jsonify({
            "error": e.name.lower().replace(" ", "_"),
            "code": e.code,
            "message": e.description,
        }).data
        response.content_type = "application/json"
        return response

    return app

@ pytest.fixture(scope="function")
def base_session():
    # Prepare a SessionData instance
    now = int(time.time())
    metadata = SessionMetadata(system={}, user={})
    session = SessionData(
        id_token="id",
        access_token="at",
        refresh_token="rt",
        scopes="openid email profile",
        userinfo={
            "sub": "user1",
            "email": "user1@example.com",
            "preferred_username": "user1",
            "name": "User One",
            "email_verified": True,
            "iss": "https://issuer",
            "aud": ["cid"],
            "groups": ["g1", {"id": "g2"}],
            "roles": ["r1"],
            "identity_set": [{"sub": "i1"}]
        },
        expires_at=now + 300,
        created_at=now - 100,
        updated_at=now - 50,
        realm="test",
        session_metadata=metadata,
        additional_tokens={}
    )
    return session

@pytest.fixture()
def fake_current_session(monkeypatch, store):
    sid = "fake_current_sid"
    skey, session = store.create_session(
        session_id=sid,
        id_token="id",
        access_token="at",
        refresh_token="rt",
        scopes="openid email profile",
        userinfo={
            "sub": "user1",
            "email": "user1@example.com",
            "preferred_username": "user1",
            "name": "User One",
            "email_verified": True,
            "iss": "https://issuer",
            "aud": ["cid"],
            "groups": ["g1", {"id": "g2"}],
            "roles": ["r1"],
            "identity_set": [{"sub": "i1"}]
        },
        realm="test"
    )

    monkeypatch.setattr(
        sm,
        "get_current_session",
        lambda: (sid, session),
    )

@pytest.fixture
def frozen_time(monkeypatch):
    fixed = 1750106643
    monkeypatch.setattr(time, "time", lambda: fixed)
    return fixed
