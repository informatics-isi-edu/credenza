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
import copy
import json
from flask import Flask
from werkzeug.http import dump_cookie
from werkzeug.exceptions import HTTPException, NotFound, Forbidden
from credenza.api import util
from credenza.api.util import get_tokens_by_scope, get_cookie_domain
from credenza.api.session.augmentation.globus_provider import GlobusSessionAugmentationProvider
from credenza.api.session.storage.session_store import SessionData, SessionMetadata


def test_has_current_session_no_sid(monkeypatch, app):
    """When extract_session_key yields no SID, we get None."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: (None, False))
        assert util.has_current_session() is None


def test_has_current_session_not_found(monkeypatch, app, store):
    """When SID exists but store.get_session_data returns None, we get None."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: ("S1", False))
        monkeypatch.setattr(store, "get_session_data", lambda sid: None)
        assert util.has_current_session() is None


def test_has_current_session_exists(monkeypatch, app, store, base_session):
    """When SID exists and store.get_session_data returns a session, we get that SID."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: ("foo", False))
        monkeypatch.setattr(store, "get_session_by_session_key", lambda skey: ("S2", copy.deepcopy(base_session)))
        assert util.has_current_session() == "S2"


def test_get_current_session_no_skey(monkeypatch, app):
    """No SID -> abort(404)."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: (None, False))
        with pytest.raises(NotFound):
            util.get_current_session()


def test_get_current_session_not_found_no_legacy(monkeypatch, app, store):
    """SID not in store, legacy API off -> abort(404)."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: ("S4", False))
        monkeypatch.setattr(store, "get_session_data", lambda sid: None)
        app.config["ENABLE_LEGACY_API"] = False
        with pytest.raises(NotFound):
            util.get_current_session()


def test_get_current_session_success(monkeypatch, app, store, base_session):
    """Valid SID in store -> returns (sid, session)."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: ("foo", False))
        monkeypatch.setattr(store, "get_session_by_session_key", lambda skey: ("S5", copy.deepcopy(base_session)))
        sid, sess = util.get_current_session()
        assert sid == "S5"
        assert isinstance(sess, SessionData)


def test_get_current_session_legacy_bearer(monkeypatch, app, store, base_session):
    with app.app_context():
        app.config["ENABLE_LEGACY_API"] = True

        # incoming key is a bearer token:
        monkeypatch.setattr(util, "extract_session_key",
                            lambda: ("BTOKEN", True))

        # first call with BTOKEN must return (None, None), second call with SID should return our new session
        new_sess = copy.deepcopy(base_session)
        def fake_get_by_key(key_arg):
            if key_arg == "BTOKEN":
                return None, None
            elif key_arg == "SID":
                return "SID", new_sess
            else:
                pytest.skip(f"Unexpected session_key lookup: {key_arg!r}")
                return None, None

        monkeypatch.setattr(store, "get_session_by_session_key", fake_get_by_key)
        monkeypatch.setattr(util, "get_augmentation_provider",
                            lambda realm: app.config["SESSION_AUGMENTATION_PROVIDERS"]["globus"])
        monkeypatch.setattr(
            GlobusSessionAugmentationProvider,
            "session_from_bearer_token",
            lambda self, bearer_token: ("SID", new_sess)
        )

        sid, sess = util.get_current_session()
        assert sid == "SID"
        assert sess is new_sess


def test_extract_session_key_from_cookie(app):
    with app.app_context():
        cookie_val = "abc.def.ghi"
        header = dump_cookie(app.config["COOKIE_NAME"], cookie_val)
        with app.test_request_context("/", environ_base={"HTTP_COOKIE": header}):
            skey, is_bearer = util.extract_session_key()
            assert skey == "abc.def.ghi" and is_bearer is False
    with app.test_request_context("/"):
        skey, _ = util.extract_session_key()
        assert skey is None


def test_extract_session_key_from_bearer_token(app):
    token = "abc.def.ghi"
    with app.test_request_context("/", headers={"Authorization": f"Bearer {token}"}):
        skey, is_bearer = util.extract_session_key()
        assert skey == token and is_bearer is True
    with app.test_request_context("/"):
        skey, is_bearer = util.extract_session_key()
        assert skey is None


def test_get_realm():
    # Create a Flask application context
    app = Flask(__name__)
    app.config["OIDC_IDP_PROFILES"] = {"realm1": {}, "realm2": {}}
    app.config["DEFAULT_REALM"] = "default_realm"
    with app.app_context():
        # Valid realm provided
        assert util.get_realm("realm1") == "realm1"
        # Invalid realm provided, should return DEFAULT_REALM
        assert util.get_realm("invalid") == "default_realm"
        # None provided, should return DEFAULT_REALM
        assert util.get_realm(None) == "default_realm"


def test_get_realm_no_default_causes_abort(monkeypatch):
    app = Flask(__name__)
    app.config["OIDC_IDP_PROFILES"] = {}
    # DEFAULT_REALM not set or empty
    app.config["DEFAULT_REALM"] = None
    with app.app_context():
        with pytest.raises(HTTPException) as excinfo:
            util.get_realm(None)
        # Ensure abort created a 400 error
        assert excinfo.value.code == 400


def test_generate_nonce_length_and_uniqueness():
    n1 = util.generate_nonce()
    n2 = util.generate_nonce()
    assert isinstance(n1, str) and len(n1) >= 32
    assert isinstance(n2, str) and n1 != n2
    n1 = util.generate_nonce()
    n2 = util.generate_nonce()
    assert isinstance(n1, str) and len(n1) >= 32
    assert isinstance(n2, str) and n1 != n2


def test_make_json_response_body_and_status():
    payload = {"msg": "ok"}
    res = util.make_json_response(payload)
    assert res.get_json() == payload
    assert res.mimetype == "application/json"


def test_get_effective_scopes_combines_scopes_and_additional_tokens(base_session):
    base_session.scopes = "openid profile"
    base_session.additional_tokens = {"svc1": {"access_token": "t1"}, "svc2": {"access_token": "t2"}}
    scopes = util.get_effective_scopes(base_session)
    assert set(scopes) == {"openid", "profile", "svc1", "svc2"}


def test_encrypt_decrypt_roundtrip():
    codec = util.AESGCMCodec("supersecretvalue")
    plaintext = {"key": "value"}
    encrypted = codec.encrypt(json.dumps(plaintext))
    decrypted = json.loads(codec.decrypt(encrypted))
    assert decrypted["key"] == "value"


def test_get_tokens_by_scope_only_primary(base_session):
    base_session.scopes = "openid email"
    base_session.access_token = "A1"
    base_session.refresh_token = "R1"
    base_session.additional_tokens = {}
    out = get_tokens_by_scope(base_session)
    assert out == {
        "openid email": {"access_token": "A1", "refresh_token": "R1"}
    }

def test_revoke_tokens_revokes_access_and_refresh(monkeypatch, app):
    """revoke_tokens() revokes access and refresh tokens per scope and emits audit events."""

    sid = "session123"
    realm = "example-realm"
    userinfo = {
        "sub": "abc123",
        "email": "user@example.org"
    }

    class DummySession:
        def __init__(self):
            self.userinfo = userinfo
            self.realm = realm
            self.session_metadata = SessionMetadata()

    # Fake token map by scope
    token_map = {
        "scope1": {
            "access_token": "access1",
            "refresh_token": "refresh1"
        },
        "scope2": {
            "access_token": "access2"  # no refresh token
        }
    }

    # Mock token client with revocation
    revoked_tokens = []

    class DummyClient:
        def revoke_token(self, scope, token, token_type_hint=None):
            revoked_tokens.append((scope, token, token_type_hint))

    audit_events = []

    # Patch everything used by revoke_tokens
    monkeypatch.setattr(util, "get_tokens_by_scope", lambda sess: token_map)
    monkeypatch.setattr(util, "audit_event",
                        lambda event, **kwargs: audit_events.append((event, kwargs)))

    class DummyFactory:
        def __init__(self):
            self.calls = []

        def get_client(self, realm, **kwargs):
            # capture for assertions if you want
            self.calls.append((realm, kwargs))
            return DummyClient()

    factory = DummyFactory()
    app.config["OIDC_CLIENT_FACTORY"] = factory

    with app.app_context():
        util.revoke_tokens(sid, DummySession())

    # Validate expected tokens revoked
    assert ("scope1", "access1", "access_token") in revoked_tokens
    assert ("scope1", "refresh1", "refresh_token") in revoked_tokens
    assert ("scope2", "access2", "access_token") in revoked_tokens
    assert len(revoked_tokens) == 3

    # Validate audit events
    expected_events = [
        ("access_token_revoked",
         {"sid": sid, "user": "user@example.org", "sub": "abc123", "realm": realm, "scope": "scope1"}),
        ("refresh_token_revoked",
         {"sid": sid, "user": "user@example.org", "sub": "abc123", "realm": realm, "scope": "scope1"}),
        ("access_token_revoked",
         {"sid": sid, "user": "user@example.org", "sub": "abc123", "realm": realm, "scope": "scope2"}),
    ]
    assert audit_events == expected_events


def test_get_tokens_by_scope_with_additional(base_session):
    base_session.scopes = "openid"
    base_session.access_token = "A1"
    base_session.refresh_token = "R1"
    base_session.additional_tokens = {
        "svc1": {"access_token": "A2"},
        "svc2": {"access_token": "A3", "refresh_token": "R3"},
    }
    out = get_tokens_by_scope(base_session)
    assert out == {
        "openid": {"access_token": "A1", "refresh_token": "R1"},
        "svc1":   {"access_token": "A2", "refresh_token": None},
        "svc2":   {"access_token": "A3", "refresh_token": "R3"},
    }


@pytest.mark.parametrize("host,config,expected", [
    ("app.example.org", "true", "example.org"),
    ("example.co.uk", "true", "example.co.uk"),
    ("localhost", "true", None),
    ("127.0.0.1", "true", None),
    ("sub.my.example.com", "true", "example.com"),
    ("app.example.org", "custom-domain.org", "custom-domain.org"),
    ("app.example.org", None, None),
    ("app.example.org", "false", None),
])
def test_get_cookie_domain(app, monkeypatch, host, config, expected):
    app.config["COOKIE_DOMAIN"] = config

    with app.test_request_context("/", base_url=f"http://{host}"):
        monkeypatch.setattr("flask.current_app", app)
        result = get_cookie_domain()
        assert result == expected