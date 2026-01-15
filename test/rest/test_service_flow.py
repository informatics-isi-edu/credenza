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
from types import SimpleNamespace
from credenza.rest import service_flow as sf
from credenza.api.session.storage.session_store import SESSION_TYPE
from credenza.api.auth.service.adapters.base import ProofContext


class StubSubject:
    def __init__(self, subject_id="svc-subject"):
        self.subject_id = subject_id

    def to_sub(self):
        return self.subject_id


class StubAdapter:
    """
    Minimal adapter stub matching the ServiceAuthAdapter interface used by service_flow.
    """
    def __init__(self, *, name="stub", matches=True, result=None):
        self._name = name
        self._matches = matches
        self._result = result

    def name(self):
        return self._name

    def matches(self, ctx):
        # ctx is a real ProofContext in these tests
        assert isinstance(ctx, ProofContext)
        return bool(self._matches)

    def verify_and_map(self, ctx, adapter_cfg):
        assert isinstance(ctx, ProofContext)
        assert self._result is not None, "StubAdapter.result must be set for verify_and_map"
        return self._result


@pytest.fixture
def client(app, monkeypatch):
    app.testing = True
    app.register_blueprint(sf.service_blueprint)

    # Ensure service auth config exists for handler
    app.config.setdefault("SERVICE_AUTH", {"adapters": {}})

    # Handler/decorators expect current_app.extensions["rate_limits"][...]
    class _DummyLimit:
        def headers(self, rem, reset):
            return {}
        def allow(self, key): return (True, 999999, 60)

    app.extensions.setdefault("rate_limits", {})
    limits = app.extensions["rate_limits"]

    # ip_rate_limited() (decorator) uses these buckets (at least 30_per_min per trace)
    limits.setdefault("30_per_min", _DummyLimit())
    limits.setdefault("60_per_min", _DummyLimit())

    # Some installs also reference these; harmless to provide
    limits.setdefault("10_per_min", _DummyLimit())
    limits.setdefault("120_per_min", _DummyLimit())

    # Bypass per-principal limiter used inside the handler body
    monkeypatch.setattr(sf, "limit_or_429", lambda *_args, **_kw: (None, None, None))

    return app.test_client()


@pytest.fixture(autouse=True)
def audit_calls(monkeypatch):
    calls = []

    def _audit(event, **kwargs):
        calls.append((event, kwargs))

    monkeypatch.setattr(sf, "audit_event", _audit)
    return calls


def _mk_result(
    *,
    realm="test",
    principal="p1",
    subject="svc-subject",
    scopes=None,
    audiences=None,
    groups=None,
    default_scopes=None,
    max_ttl_seconds=1800,
    proof_type="stub",
):
    """
    Build a minimal ServiceIssueResult-shaped object that service_flow expects.
    We use SimpleNamespace to avoid coupling to adapter dataclasses while keeping shape.
    """
    scopes = scopes if scopes is not None else ["s1"]
    audiences = audiences if audiences is not None else ["a1"]
    groups = groups if groups is not None else []

    return SimpleNamespace(
        realm=realm,
        proof={"type": proof_type, "principal": principal},
        subject=StubSubject(subject),
        authz=SimpleNamespace(
            scopes=scopes,
            audiences=audiences,
            groups=groups,
            email="svc@example.com",
            name="Service Principal",
        ),
        policy=SimpleNamespace(
            default_scopes=default_scopes if default_scopes is not None else [],
            max_ttl_seconds=max_ttl_seconds,
        ),
    )


def test_proof_context_get_getlist_header():
    ctx = ProofContext(form={"a": ["1", "2"], "b": "x"}, headers={"X-Test": "y"})
    assert ctx.get("a") == "1"
    assert ctx.getlist("a") == ["1", "2"]
    assert ctx.get("b") == "x"
    assert ctx.getlist("b") == ["x"]
    assert ctx.header("x-test") == "y"


def test_issue_creates_service_session_with_expected_fields(monkeypatch):
    now = 1_700_000_000
    ttl = 1234

    # Freeze time inside service_flow module
    monkeypatch.setattr(sf.time, "time", lambda: now)

    subject = "svc-123"
    proof = {"type": "client_secret", "principal": "p1"}
    authz = {
        "scopes": ["s1", "s2"],
        "audiences": ["a1", "a2"],
        "groups": ["g1"],
        "email": "svc@example.com",
        "name": "Service Principal",
        "realm": "test",
    }

    calls = {}

    class StubStore:
        def generate_session_id(self):
            return "SID-1"

        def generate_session_key(self):
            return "AT-1"

        def create_session(self, **kwargs):
            calls.update(kwargs)
            return ("SESSION-KEY-1", None)

    store = StubStore()

    session_key, out_ttl = sf.issue(
        store=store,
        subject=subject,
        authz=authz,
        ttl=ttl,
        proof=proof,
    )

    assert session_key == "SESSION-KEY-1"
    assert out_ttl == ttl

    # Verify create_session() call contract
    assert calls["session_id"] == "SID-1"
    assert calls["session_type"] == SESSION_TYPE.service
    assert calls["access_token"] == "AT-1"
    assert calls["scopes"] == ["s1", "s2"]
    assert calls["realm"] == "test"

    # userinfo mapping
    assert calls["userinfo"] == {
        "sub": subject,
        "aud": ["a1", "a2"],
        "groups": ["g1"],
        "name": "Service Principal",
        "email": "svc@example.com",
    }

    # expiry + ttl
    assert calls["expires_at"] == now + ttl
    assert calls["session_ttl"] == ttl

    # proof stored in metadata
    assert calls["metadata"] == {"proof": proof}

    # important flag: opaque access token is the session key
    assert calls["use_access_token_as_session_key"] is True


def test_issue_service_token_invalid_grant_type_400(client, audit_calls, monkeypatch):
    # Grant type check runs before adapter loop
    monkeypatch.setattr(sf, "ADAPTERS", [StubAdapter(matches=False)], raising=False)

    resp = client.post("/service/token", data={"grant_type": "wrong:urn"})
    assert resp.status_code == 400

    events = [ev for ev, _ in audit_calls]
    assert "service_token_invalid_grant_type" in events, audit_calls


def test_issue_service_token_no_adapter_match_400(client, audit_calls, monkeypatch):
    monkeypatch.setattr(sf, "ADAPTERS", [StubAdapter(matches=False)], raising=False)

    resp = client.post("/service/token", data={"grant_type": sf.DEFAULT_SERVICE_AUTH_URN})
    assert resp.status_code == 400

    events = [ev for ev, _ in audit_calls]
    assert "service_token_no_adapter_match" in events, audit_calls


def test_issue_service_token_missing_scope_no_defaults_400(client, audit_calls, monkeypatch, app):
    res = _mk_result(scopes=["s1"], default_scopes=[], audiences=["a1"])
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    # No "scope" in request, and no local default_scopes -> 400
    resp = client.post("/service/token", data={"grant_type": sf.DEFAULT_SERVICE_AUTH_URN})
    assert resp.status_code == 400

    events = [ev for ev, _ in audit_calls]
    assert "service_token_missing_scope" in events, audit_calls


def test_issue_service_token_missing_scope_uses_defaults_200(client, audit_calls, monkeypatch, app):
    res = _mk_result(scopes=["s1", "s2"], default_scopes=["s1"], audiences=["a1"])
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    issued = {}

    def _issue(**kwargs):
        issued.update(kwargs)
        return ("tok-default-scope", kwargs["ttl"])

    monkeypatch.setattr(sf, "issue", lambda **kw: _issue(**kw))

    resp = client.post("/service/token", data={"grant_type": sf.DEFAULT_SERVICE_AUTH_URN})
    assert resp.status_code == 200
    assert resp.json["access_token"] == "tok-default-scope"
    assert resp.json["expires_in"] == res.policy.max_ttl_seconds  # requested_ttl absent -> cap

    assert issued["authz"]["scopes"] == ["s1"]

    events = [ev for ev, _ in audit_calls]
    assert "service_token_issued" in events, audit_calls


def test_issue_service_token_scope_violation_403(client, audit_calls, monkeypatch, app):
    res = _mk_result(scopes=["s1"], default_scopes=[], audiences=["a1"])
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    # Request disallowed scope
    resp = client.post(
        "/service/token",
        data={"grant_type": sf.DEFAULT_SERVICE_AUTH_URN, "scope": "s2"},
    )
    assert resp.status_code == 403

    events = [ev for ev, _ in audit_calls]
    assert "service_token_scope_violation" in events, audit_calls


def test_issue_service_token_no_allowed_audiences_misconfig_500(client, audit_calls, monkeypatch, app):
    res = _mk_result(scopes=["s1"], default_scopes=["s1"], audiences=[])
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    resp = client.post(
        "/service/token",
        data={"grant_type": sf.DEFAULT_SERVICE_AUTH_URN},
    )
    assert resp.status_code == 500

    events = [ev for ev, _ in audit_calls]
    assert "service_token_issue_misconfig" in events, audit_calls


def test_issue_service_token_audience_escalation_attempt_403(client, audit_calls, monkeypatch, app):
    res = _mk_result(scopes=["s1"], default_scopes=["s1"], audiences=["a1"])
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    # Request disallowed audience
    resp = client.post(
        "/service/token",
        data={
            "grant_type": sf.DEFAULT_SERVICE_AUTH_URN,
            "scope": "s1",
            "audience": ["a2"],
        },
    )
    assert resp.status_code == 403

    events = [ev for ev, _ in audit_calls]
    assert "service_token_audience_escalation_attempt" in events, audit_calls


def test_issue_service_token_audience_excessive_400(client, audit_calls, monkeypatch, app):
    # More than 32 allowed audiences; no requested audiences -> defaults to allowed -> should 400
    allowed = [f"a{i}" for i in range(40)]
    res = _mk_result(scopes=["s1"], default_scopes=["s1"], audiences=allowed)
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    resp = client.post(
        "/service/token",
        data={"grant_type": sf.DEFAULT_SERVICE_AUTH_URN, "scope": "s1"},
    )
    assert resp.status_code == 400

    events = [ev for ev, _ in audit_calls]
    assert "service_token_audience_excessive" in events, audit_calls


def test_issue_service_token_bad_ttl_400(client, audit_calls, monkeypatch, app):
    res = _mk_result(scopes=["s1"], default_scopes=["s1"], audiences=["a1"])
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    resp = client.post(
        "/service/token",
        data={
            "grant_type": sf.DEFAULT_SERVICE_AUTH_URN,
            "scope": "s1",
            "requested_ttl_seconds": "abc",
        },
    )
    assert resp.status_code == 400

    events = [ev for ev, _ in audit_calls]
    assert "service_token_bad_ttl" in events, audit_calls


def test_issue_service_token_clamped_ttl_audited_200(client, audit_calls, monkeypatch, app):
    res = _mk_result(scopes=["s1"], default_scopes=["s1"], audiences=["a1"], max_ttl_seconds=100)
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    monkeypatch.setattr(sf, "issue", lambda **kw: ("tok", kw["ttl"]))

    resp = client.post(
        "/service/token",
        data={
            "grant_type": sf.DEFAULT_SERVICE_AUTH_URN,
            "scope": "s1",
            "requested_ttl_seconds": "200",
        },
    )
    assert resp.status_code == 200
    assert resp.json["access_token"] == "tok"
    assert resp.json["expires_in"] == 100

    events = [ev for ev, _ in audit_calls]
    assert "service_token_clamped_ttl" in events, audit_calls
    assert "service_token_issued" in events, audit_calls


def test_issue_service_token_success_200(client, audit_calls, monkeypatch, app):
    res = _mk_result(
        scopes=["s1", "s2"],
        default_scopes=["s1"],
        audiences=["a1", "a2"],
        max_ttl_seconds=1800,
        principal="principal-1",
        subject="svc-123",
        groups=["g1"],
    )
    adapter = StubAdapter(matches=True, result=res)
    monkeypatch.setattr(sf, "ADAPTERS", [adapter], raising=False)

    with app.app_context():
        app.config["SERVICE_AUTH"] = {"adapters": {adapter.name(): {}}}

    issued = {}

    def _issue(**kwargs):
        issued.update(kwargs)
        return ("tok-success", kwargs["ttl"])

    monkeypatch.setattr(sf, "issue", lambda **kw: _issue(**kw))

    resp = client.post(
        "/service/token",
        data={
            "grant_type": sf.DEFAULT_SERVICE_AUTH_URN,
            "scope": "s1 s2",
            "audience": ["a1"],  # narrowed request
            "requested_ttl_seconds": "1200",
        },
    )
    assert resp.status_code == 200
    assert resp.json["access_token"] == "tok-success"
    assert resp.json["expires_in"] == 1200

    # Verify issue() got what we expect
    assert issued["subject"] == "svc-123"
    assert issued["authz"]["scopes"] == ["s1", "s2"]
    assert issued["authz"]["audiences"] == ["a1"]
    assert issued["ttl"] == 1200

    events = [ev for ev, _ in audit_calls]
    assert "service_token_audience_requested" in events, audit_calls
    assert "service_token_audience_narrowed" in events, audit_calls
    assert "service_token_issued" in events, audit_calls


def test_revoke_service_token_denied_non_service_403(client, audit_calls, monkeypatch, app, store):
    # Handler uses imported get_current_session from util; patch the local symbol
    sess = SimpleNamespace(session_type=SESSION_TYPE.user, realm="test", userinfo={"sub": "u"})
    monkeypatch.setattr(sf, "get_current_session", lambda: ("sid-user", sess))

    with app.app_context():
        app.config["SESSION_STORE"] = store

    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda sid: deleted.append(sid))

    resp = client.delete("/service/token")
    assert resp.status_code == 403
    assert deleted == []

    events = [ev for ev, _ in audit_calls]
    assert "service_token_revoke_denied" in events, audit_calls


def test_revoke_service_token_success_204(client, audit_calls, monkeypatch, app, store):
    sess = SimpleNamespace(session_type=SESSION_TYPE.service, realm="test", userinfo={"sub": "svc-123"})
    monkeypatch.setattr(sf, "get_current_session", lambda: ("sid-svc", sess))

    with app.app_context():
        app.config["SESSION_STORE"] = store

    deleted = []
    monkeypatch.setattr(store, "delete_session", lambda sid: deleted.append(sid))

    resp = client.delete("/service/token")
    assert resp.status_code == 204
    assert deleted == ["sid-svc"]

    events = [ev for ev, _ in audit_calls]
    assert "service_token_revoked" in events, audit_calls


def test_norm_str_list_basic():
    assert sf.norm_str_list(None) == []
    assert sf.norm_str_list("") == []
    assert sf.norm_str_list(" a ") == ["a"]
    assert sf.norm_str_list([" a ", "", None, "b"]) == ["a", "b"]


def test_clamp_ttl_basic():
    # cap <= 0 -> DEFAULT_MAX_TTL
    assert sf.clamp_ttl(0, None) == sf.DEFAULT_MAX_TTL
    assert sf.clamp_ttl(-1, 10) == sf.DEFAULT_MAX_TTL

    # requested None -> cap
    assert sf.clamp_ttl(100, None) == 100

    # requested invalid -> cap
    assert sf.clamp_ttl(100, "bad") == 100

    # requested <= 0 -> cap
    assert sf.clamp_ttl(100, 0) == 100
    assert sf.clamp_ttl(100, -5) == 100

    # clamp to cap
    assert sf.clamp_ttl(100, 200) == 100
    assert sf.clamp_ttl(100, 50) == 50
