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
import base64
from flask import Flask
from werkzeug.http import dump_cookie
from werkzeug.exceptions import HTTPException, NotFound
from credenza.api.common import util
from credenza.api.session.augmentation.globus_provider import GlobusSessionAugmentationProvider
from credenza.api.session.storage.session_store import SessionData, SessionMetadata, SessionType
from credenza.api.common.util import get_tokens_by_scope, parse_basic_auth, collapse_str_list, validate_resource_string

def test_get_current_session_no_skey(monkeypatch, app):
    """No SID -> abort(404)."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: (None, False))
        with pytest.raises(NotFound):
            util.get_current_session()


def test_get_current_session_no_skey_no_abort(monkeypatch, app):
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: (None, False))
        sid, session = util.get_current_session(dont_abort=True)
        assert sid is None
        assert session is None


def test_get_current_session_not_found_no_legacy(monkeypatch, app, store):
    """SID not in store, legacy API off -> abort(404)."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: ("S4", False))
        monkeypatch.setattr(store, "get_session_data", lambda sid: None)
        app.config["ENABLE_LEGACY_API"] = False
        with pytest.raises(NotFound):
            util.get_current_session()

def test_get_current_session_not_found_no_legacy_no_abort(monkeypatch, app, store):
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: ("S4", False))
        monkeypatch.setattr(store, "get_session_data", lambda sid: None)
        app.config["ENABLE_LEGACY_API"] = False
        sid, session = util.get_current_session(dont_abort=True)
        assert sid is None
        assert session is None


def test_get_current_session_success(monkeypatch, app, store, base_session):
    """Valid SID in store -> returns (sid, session)."""
    with app.app_context():
        monkeypatch.setattr(util, "extract_session_key", lambda: ("foo", False))
        monkeypatch.setattr(store, "get_active_session_by_session_key",
                            lambda skey: ("S5", copy.deepcopy(base_session)))
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

        monkeypatch.setattr(store, "get_active_session_by_session_key", fake_get_by_key)
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


def test_get_effective_scopes_combines_scopes_and_additional_tokens(base_session):
    base_session.scopes = "openid profile"
    base_session.additional_tokens = {"svc1": {"access_token": "t1"}, "svc2": {"access_token": "t2"}}
    scopes = util.get_effective_scopes(base_session)
    assert set(scopes) == {"openid", "profile", "svc1", "svc2"}


def test_get_tokens_by_scope_only_primary(base_session):
    base_session.scopes = "openid email"
    base_session.access_token = "A1"
    base_session.refresh_token = "R1"
    base_session.additional_tokens = {}
    out = get_tokens_by_scope(base_session)
    assert out == {
        "openid email": {"access_token": "A1", "refresh_token": "R1"}
    }


def test_revoke_tokens_revokes_access_and_refresh(monkeypatch, app, base_session):
    """revoke_tokens() revokes access and refresh tokens per scope and emits audit events."""

    sid = "session123"
    realm = "example-realm"
    userinfo = {
        "sub": "abc123",
        "email": "user@example.org"
    }

    # Use the shared base_session fixture, but copy & override userinfo/realm to match test expectations
    sess = copy.deepcopy(base_session)
    sess.userinfo = userinfo
    sess.realm = realm
    sess._session_type = SessionType.USER
    sess.session_metadata = SessionMetadata()

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
        util.revoke_tokens(sid, sess)

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


def test_retrying_requests_session_mounts_and_retries_configured():
    s = util.retrying_requests_session(total=5, backoff_factor=0.1)
    assert "http://" in s.adapters
    assert "https://" in s.adapters

    https_adapter = s.adapters["https://"]
    retry = https_adapter.max_retries

    # Sanity checks on retry config
    assert retry.total == 5
    assert retry.backoff_factor == 0.1
    # default allowed_methods in util is GET-only unless overridden
    assert retry.allowed_methods is not None
    assert "GET" in retry.allowed_methods


def test_singleton_returns_string():
    result = collapse_str_list(["value"])
    assert isinstance(result, str)
    assert result == "value"


def test_singleton_after_dedup_returns_string():
    # duplicate entries collapse to one unique value
    result = collapse_str_list(["x", "x"])
    assert isinstance(result, str)
    assert result == "x"


def test_multiple_unique_returns_list():
    result = collapse_str_list(["a", "b"])
    assert isinstance(result, list)
    assert result == ["a", "b"]


def test_multiple_unique_sorted_list():
    # collapse_str_list should preserve normalize_str_list sorting behavior
    result = collapse_str_list(["b", "a"])
    assert isinstance(result, list)
    assert result == ["a", "b"]


def test_parse_basic_auth_valid_and_invalid():
    # valid basic
    b64 = base64.b64encode(f"cid1:s1".encode("utf-8")).decode("ascii")
    header = f"Basic {b64}"
    parsed = parse_basic_auth(header)
    assert parsed == {"client_id": "cid1", "client_secret": "s1"}

    # wrong scheme
    assert parse_basic_auth("Bearer abcdef") is None

    # malformed base64
    assert parse_basic_auth("Basic !!!notbase64!!!") is None

    # no colon after decode
    b64 = base64.b64encode(b"nocolon").decode("ascii")
    assert parse_basic_auth(f"Basic {b64}") is None

    # empty header
    assert parse_basic_auth("") is None
    assert parse_basic_auth(None) is None


def test_validate_resource_string_none_raises():
    with pytest.raises(ValueError, match="resource value required"):
        validate_resource_string(None)


def test_validate_resource_string_empty_raises():
    with pytest.raises(ValueError, match="empty resource value not allowed"):
        validate_resource_string("   ")


def test_validate_resource_string_accepts_urn_verbatim_and_strips_whitespace():
    # leading/trailing whitespace is stripped, URN preserved otherwise
    inp = "  urn:example:resource:all  "
    out = validate_resource_string(inp)
    assert out == "urn:example:resource:all"


def test_validate_resource_string_accepts_urn_case_insensitive_prefix():
    # function uses .lower().startswith("urn:"), so mixed case still treated as URN
    inp = "URN:EXAMPLE:CASE"
    out = validate_resource_string(inp)
    assert out == "URN:EXAMPLE:CASE"


def test_validate_resource_string_requires_scheme_and_host():
    with pytest.raises(ValueError, match="scheme and host required"):
        validate_resource_string("example.com/no-scheme")

    with pytest.raises(ValueError, match="scheme and host required"):
        validate_resource_string("/just/a/path")


def test_validate_resource_string_disallows_userinfo_in_netloc():
    # user:pass@host should be disallowed
    with pytest.raises(ValueError, match="must not contain userinfo"):
        validate_resource_string("https://user:pass@example.com/path")


def test_validate_resource_string_accepts_https_urls():
    inp = "https://example.com/some/path?query=1"
    out = validate_resource_string(inp)
    assert out == inp


def test_validate_resource_string_accepts_https_uppercase_scheme_and_host():
    # scheme and host case should be tolerated; returned value is original string
    inp = "HTTPS://EXAMPLE.COM/UPPER"
    out = validate_resource_string(inp)
    assert out == inp


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_validate_resource_string_allows_http_for_localhost_and_127(host):
    inp = f"http://{host}:8080/path"
    out = validate_resource_string(inp)
    assert out == inp


def test_validate_resource_string_rejects_http_for_non_localhost():
    with pytest.raises(ValueError, match="network resource URIs must use https"):
        validate_resource_string("http://example.com/path")
