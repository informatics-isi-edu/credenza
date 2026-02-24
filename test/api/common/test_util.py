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
import uuid
import base64
from flask import Flask, jsonify, g
from werkzeug.http import dump_cookie
from werkzeug.exceptions import HTTPException, NotFound
from credenza.api.common import util
from credenza.api.common.util import get_tokens_by_scope, get_cookie_domain
from credenza.api.session.augmentation.globus_provider import GlobusSessionAugmentationProvider
from credenza.api.session.storage.session_store import SessionData, SessionMetadata, SessionType


def test_decrypt_invalid_ciphertext_returns_none():
    codec = util.AESGCMCodec("supersecretvalue")
    assert codec.decrypt("not-a-valid-token") is None


def test_decrypt_tampered_ciphertext_returns_none():
    codec = util.AESGCMCodec("supersecretvalue")
    plaintext = json.dumps({"k": "v"})

    token = codec.encrypt(plaintext)

    # Outer layer is base64(urlsafe) encoded JSON bytes
    raw = base64.urlsafe_b64decode(token.encode())
    assert raw, "expected non-empty decoded payload"

    # Flip one byte deterministically (not the first/last to avoid trivial decode issues)
    b = bytearray(raw)
    idx = min(5, len(b) - 1)
    b[idx] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(b)).decode()

    # GCM integrity should fail => decrypt() returns None
    assert codec.decrypt(tampered) is None



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

def test_get_current_session_service_absolute_lifetime_exceeded_401_deletes_and_audits(
    monkeypatch, app, store, base_session):
    sid = "svc-abs-life"
    now = 1_700_000_000  # deterministic "current" time

    sess = copy.deepcopy(base_session)
    sess._session_type = SessionType.SERVICE
    sess.created_at = now - 100  # created exactly abs_life seconds ago => hard_stop == now
    sess.expires_at = now + 10_000

    sess.session_metadata.system = dict(sess.session_metadata.system or {})
    sess.session_metadata.system["service_policy"] = {
        "absolute_lifetime_seconds": 100,  # hard stop at created_at + 100 == now
    }

    audit_calls = []
    monkeypatch.setattr(util, "audit_event", lambda ev, **kw: audit_calls.append((ev, kw)))

    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda s: deleted.append(s))

    with app.app_context():
        app.config["SESSION_STORE"] = store
        app.config["ENABLE_LEGACY_API"] = False

        # Drive get_current_session() down the "service session hard-stop" branch
        monkeypatch.setattr(util, "extract_session_key", lambda: ("SKEY", False))
        monkeypatch.setattr(store, "get_session_by_session_key", lambda skey: (sid, sess))

        # Freeze util's time source (get_current_session imports time in util module)
        monkeypatch.setattr(util.time, "time", lambda: float(now))

        with pytest.raises(HTTPException) as excinfo:
            util.get_current_session()

        assert excinfo.value.code == 401

    # Must delete the session
    assert deleted == [sid]

    # Must audit the lifetime exceeded event
    events = [ev for ev, _ in audit_calls]
    assert "service_session_absolute_lifetime_exceeded" in events, audit_calls

    # Optional: verify key audit payload fields
    _, kw = next((ev, kw) for ev, kw in audit_calls if ev == "service_session_absolute_lifetime_exceeded")
    assert kw["session_id"] == sid
    assert kw["created_at"] == sess.created_at
    assert kw["absolute_lifetime_seconds"] == 100
    assert kw["realm"] == sess.realm


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


def test_client_ip_returns_remote_addr(app):
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "1.2.3.4"}):
        assert util.client_ip(util.request) == "1.2.3.4"


def test_client_ip_unknown_when_missing(app):
    with app.test_request_context("/", environ_base={}):
        assert util.client_ip(util.request) == "unknown"


def test_get_correlation_id_prefers_traceparent(app):
    with app.test_request_context("/", headers={"traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"}):
        assert util.get_correlation_id(util.request) == "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"


@pytest.mark.parametrize("header_name", ["X-Request-Id", "X-Request-ID", "x-request-id",
                                        "X-Correlation-Id", "X-Correlation-ID", "x-correlation-id",
                                        "X-Amzn-Trace-Id", "x-amzn-trace-id"])
def test_get_correlation_id_uses_common_headers(app, header_name):
    with app.test_request_context("/", headers={header_name: "RID-123"}):
        assert util.get_correlation_id(util.request) == "RID-123"


def test_get_correlation_id_generates_uuid_last_resort(app, monkeypatch):
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID("12345678-1234-5678-1234-567812345678"))
    with app.test_request_context("/", headers={}):
        assert util.get_correlation_id(util.request) == "12345678-1234-5678-1234-567812345678"


def test_ip_rate_limited_allows_and_attaches_headers(app, monkeypatch):
    # Bucket that always allows
    class DummyBucket:
        def allow(self, key):
            return True, 7, 42  # allowed, remaining, reset_s

        def headers(self, remaining, reset_s):
            return {"X-RateLimit-Remaining": str(remaining), "X-RateLimit-Reset": str(reset_s)}

    # Ensure rate limits exist
    app.extensions.setdefault("rate_limits", {})
    app.extensions["rate_limits"]["30_per_min"] = DummyBucket()
    app.extensions["rate_limits"]["10_per_min"] = DummyBucket()

    # Stable client IP
    monkeypatch.setattr(util, "client_ip", lambda req: "1.2.3.4")

    @util.ip_rate_limited()
    def handler():
        # Ensure decorator stashed g.rate_limit
        assert "bucket" in g.rate_limit
        assert g.rate_limit["remaining"] == 7
        assert g.rate_limit["reset"] == 42
        return jsonify({"ok": True}), 200

    with app.test_request_context("/x", method="GET"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True}
        # Headers added by decorator
        assert resp.headers.get("X-RateLimit-Remaining") == "7"
        assert resp.headers.get("X-RateLimit-Reset") == "42"


def test_ip_rate_limited_denies_429_and_audits(app, monkeypatch):
    audit_events = []
    monkeypatch.setattr(util, "audit_event", lambda event, **kwargs: audit_events.append((event, kwargs)))

    class DenyBucket:
        def allow(self, key):
            return False, 0, 11

        def headers(self, remaining, reset_s):
            return {"X-RateLimit-Remaining": str(remaining), "X-RateLimit-Reset": str(reset_s)}

    app.extensions.setdefault("rate_limits", {})
    app.extensions["rate_limits"]["30_per_min"] = DenyBucket()
    app.extensions["rate_limits"]["10_per_min"] = DenyBucket()

    monkeypatch.setattr(util, "client_ip", lambda req: "9.9.9.9")

    @util.ip_rate_limited()
    def handler():
        return jsonify({"ok": True}), 200  # should never run

    with app.test_request_context("/x", method="POST"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 429
        data = resp.get_json()
        assert data["error"] == "rate_limited"
        assert "Too many requests:" in data["detail"]
        assert resp.headers.get("Retry-After") == "11"
        assert resp.headers.get("X-RateLimit-Remaining") == "0"
        assert resp.headers.get("X-RateLimit-Reset") == "11"

    assert any(ev == "request_rate_limited" for ev, _ in audit_events), audit_events

def test_ip_rate_limited_bypass_skips_limits_and_limit_or_429(app, monkeypatch):
    app.config["ENABLE_RATE_LIMITING"] = False

    # Make it obvious if the decorator tries to rate limit anyway
    app.extensions.pop("rate_limits", None)

    def boom(*args, **kwargs):
        raise AssertionError("limit_or_429 should not be called when ENABLE_RATE_LIMITING is False")

    monkeypatch.setattr(util, "limit_or_429", boom)

    @util.ip_rate_limited()
    def handler():
        return jsonify({"ok": True}), 200

    with app.test_request_context("/x", method="GET"):
        resp = app.make_response(handler())
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True}
        # Optional: ensure decorator didn't stash rate-limit info
        assert not hasattr(g, "rate_limit")


def test_perf_logged_noop_when_disabled(app):
    # Should not log anything or change return value
    app.config["DEBUG_PERF"] = False

    class DummyLogger:
        def __init__(self):
            self.debug_calls = []
            self.warning_calls = []

        def debug(self, msg):
            self.debug_calls.append(msg)

        def warning(self, msg):
            self.warning_calls.append(msg)

    log = DummyLogger()

    @util.perf_logged(warn_ms=1, logger=log)
    def handler():
        return ("ok", 200)

    with app.test_request_context("/p", method="GET"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 200
        assert resp.get_data(as_text=True) == "ok"

    assert log.debug_calls == []
    assert log.warning_calls == []


def test_perf_logged_debug_when_enabled_and_under_warn(app):
    app.config["DEBUG_PERF"] = True

    class DummyLogger:
        def __init__(self):
            self.debug_calls = []
            self.warning_calls = []

        def debug(self, msg):
            self.debug_calls.append(msg)

        def warning(self, msg):
            self.warning_calls.append(msg)

    log = DummyLogger()

    @util.perf_logged(warn_ms=10_000, logger=log)  # huge threshold => debug
    def handler():
        return ("ok", 200)

    with app.test_request_context("/p", method="GET"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 200

    assert len(log.debug_calls) == 1
    assert log.warning_calls == []
    assert "GET" in log.debug_calls[0]
    assert "took" in log.debug_calls[0]


def test_perf_logged_warning_when_enabled_and_over_warn(app, monkeypatch):
    app.config["DEBUG_PERF"] = True

    # Force perf_counter to simulate elapsed >= warn_ms
    seq = {"i": 0}

    def fake_perf_counter():
        seq["i"] += 1
        # first call start=0.0, second call end=1.0 => 1000ms
        return 0.0 if seq["i"] == 1 else 1.0

    monkeypatch.setattr(util.time, "perf_counter", fake_perf_counter)

    class DummyLogger:
        def __init__(self):
            self.debug_calls = []
            self.warning_calls = []

        def debug(self, msg):
            self.debug_calls.append(msg)

        def warning(self, msg):
            self.warning_calls.append(msg)

    log = DummyLogger()

    @util.perf_logged(warn_ms=500, logger=log)  # 1000ms >= 500 => warning
    def handler():
        return ("ok", 200)

    with app.test_request_context("/p", method="GET"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 200

    assert log.debug_calls == []
    assert len(log.warning_calls) == 1
    assert "took" in log.warning_calls[0]


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
