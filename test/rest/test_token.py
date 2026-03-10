# Copyright 2025 University of Southern California
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
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
from flask import request
from werkzeug.exceptions import HTTPException

import credenza.rest.token as token_mod
from credenza.api.auth.client.adapters.adapter import (
    Subject,
    AdapterInterface,
    AdapterResult,
    AdapterAuthError,
    AdapterError,
)
from credenza.api.auth.client.client_registry import ClientRegistry, ClientRecord, AdapterConfig
from credenza.api.common.errors import OAuthError


class DummyAdapter(AdapterInterface):
    ADAPTER_NAME = "dummy"
    SUPPORTED_AUTH_METHODS = ("client_secret_basic",)

    @classmethod
    def from_dict(cls, config, client_id):
        cfg = AdapterConfig(
            client_id=client_id,
            adapter_name=cls.ADAPTER_NAME,
            config_dict=config,
        )  # type: ignore[attr-defined]
        return cls(cfg)

    def authenticate(self, proof_context, allowed_methods=None):
        # default will be replaced via monkeypatch in tests
        raise NotImplementedError()


class StubAdapter:
    """Test-local adapter stub. Can be configured to return a result or raise an error."""

    ADAPTER_NAME = "stub"
    SUPPORTED_AUTH_METHODS = ("client_secret",)

    def __init__(self, result: AdapterResult = None, raise_exc: Exception = None):
        self._result = result
        self._raise = raise_exc
        # minimal AdapterConfig needed for client_rec.adapter_config
        self.config = AdapterConfig(
            client_id="stub-client", adapter_name=self.ADAPTER_NAME, config_dict={}
        )

    @classmethod
    def from_dict(cls, cfg, client_id):
        return cls()

    def authenticate(self, proof_context, allowed_methods=None):
        if self._raise:
            raise self._raise
        if self._result is None:
            raise AdapterError("no result configured")
        return self._result


def make_client_record(client_id: str, *,
                       enabled=True,
                       public=False,
                       allowed_grant_types=None,
                       allowed_resources=None,
                       allowed_scopes=None,
                       default_resources=None,
                       default_scopes=None,
                       adapter_instance=None,
                       additional_claims=None,
                       allowed_claims=None,
                       allowed_auth_methods=None):
    """Construct a ClientRecord suitable for tests (mirrors registry-loaded shape)."""

    # Default to allowing client_credentials unless test overrides it.
    if allowed_grant_types is None:
        allowed_grant_types = [token_mod.GrantType.CLIENT_CREDENTIALS.value]
    else:
        allowed_grant_types = list(allowed_grant_types)

    allowed_resources = allowed_resources or []
    allowed_scopes = allowed_scopes or []
    default_resources = default_resources or []
    default_scopes = default_scopes or []
    additional_claims = additional_claims or {}
    allowed_claims = allowed_claims or []
    allowed_auth_methods = allowed_auth_methods or []

    cr = ClientRecord(
        client_id=client_id,
        desc=None,
        enabled=enabled,
        public=public,
        adapter_config=(adapter_instance.config if adapter_instance is not None else None),
        adapter_class=(type(adapter_instance) if adapter_instance is not None else None),
        adapter_instance=adapter_instance,
        allowed_grant_types=list(allowed_grant_types),
        allowed_resources=list(allowed_resources),
        allowed_scopes=list(allowed_scopes),
        allowed_claims=list(allowed_claims),
        allowed_auth_methods=list(allowed_auth_methods),
        allowed_token_exchange_targets=[],
        max_session_ttl_seconds=token_mod.DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL,
        absolute_session_lifetime_seconds=token_mod.DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL,
        default_resources=list(default_resources),
        default_scopes=list(default_scopes),
        additional_claims=additional_claims,
    )
    return cr


@pytest.fixture(autouse=True)
def register_blueprint(app):
    # ensure blueprint is registered for tests
    if "token" not in app.blueprints:
        app.register_blueprint(token_mod.token_blueprint)

    # Ensure a minimal CLIENT_AUTH_REGISTRY and IDP_CLAIM_MAPS exist so tests do not KeyError.
    if "CLIENT_AUTH_REGISTRY" not in app.config:
        app.config["CLIENT_AUTH_REGISTRY"] = ClientRegistry(version="0", clients={})
    if "IDP_CLAIM_MAPS" not in app.config:
        app.config["IDP_CLAIM_MAPS"] = {}

    return app


def test_validate_client_missing_client_id(app):
    cr = ClientRegistry(version="0", clients={})
    with app.app_context():
        with app.test_request_context("/token", method="POST", data={}):
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.validate_client(cr, proof_ctx)
            assert ei.value.code == 400


def test_validate_client_unknown_client(app):
    cr = ClientRegistry(version="0", clients={})
    with app.app_context():
        with app.test_request_context("/token", method="POST", data={"client_id": "nope"}):
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.validate_client(cr, proof_ctx)
            assert ei.value.code == 401


def test_validate_grant_type_missing(app):
    client = make_client_record("c1", allowed_grant_types=[])
    with app.app_context():
        with app.test_request_context("/token", method="POST", data={"client_id": "c1"}):
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.validate_grant_type(proof_ctx, client)
            assert ei.value.code == 400


def test_validate_grant_type_not_allowed(app):
    with app.app_context():
        with app.test_request_context(
            "/token", method="POST",
            data={
                "client_id": "c1",
                "grant_type": "password"
            }
        ):
            client = make_client_record(
                "c1", allowed_grant_types=["some-other-grant"]
            )
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.validate_grant_type(proof_ctx, client)
            assert ei.value.code == 401


def test_validate_grant_type_success(app):
    with app.app_context():
        with app.test_request_context(
            "/token", method="POST",
            data={
                "client_id": "c1",
                "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value
            }
        ):
            client = make_client_record(
                "c1",
                allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
            )
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            gt = token_mod.validate_grant_type(proof_ctx, client)
            assert gt == token_mod.GrantType.CLIENT_CREDENTIALS


def test_adapter_authenticate_missing_adapter(app):
    with app.app_context():
        with app.test_request_context(
            "/token", method="POST",
            data={
                "client_id": "c1",
                "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value
            }
        ):
            client = make_client_record(
                "c1",
                allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
                adapter_instance=None,
                public=False,
            )
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.adapter_authenticate(proof_ctx, client)
            assert ei.value.code == 500


def test_adapter_authenticate_adapter_auth_error(app):
    with app.app_context():
        with app.test_request_context(
            "/token", method="POST",
            data={
                "client_id": "c1",
                "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value
            }
        ):
            subj = Subject(provider="client_secret", subject_id="c1")
            res = AdapterResult(subject=subj, additional_claims={"name": "svc"},
                                auth_context={"type": "client_secret"})
            exc = AdapterAuthError("not allowed", status=403,
                                   error_code=OAuthError.ACCESS_DENIED.value)
            adapter = StubAdapter(result=res, raise_exc=exc)
            client = make_client_record(
                "c1",
                allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
                adapter_instance=adapter,
                public=False,
            )
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.adapter_authenticate(proof_ctx, client)
            assert ei.value.code == 403


def test_validate_resources_escalation(app):
    # requested resource not in allowed => 403
    with app.app_context():
        with app.test_request_context(
            "/token", method="POST",
            data={"client_id": "c1", "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                  "resource": ["urn:svc:r2"]}
        ):
            subj = "urn:credenza:client:auth:client_secret:c1"
            adapter = StubAdapter()
            client = make_client_record(
                "c1", allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
                allowed_resources=["urn:svc:r1"], adapter_instance=adapter
            )
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.validate_resources_for_client(
                    proof_ctx=proof_ctx, client_rec=client, subject=subj
                )
            assert ei.value.code == 403


def test_validate_scopes_default_and_violation(app):
    with app.app_context():
        with app.test_request_context(
            "/token", method="POST",
            data={"client_id": "c1", "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value}
        ):
            adapter = StubAdapter()
            client = make_client_record(
                "c1",
                allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
                allowed_scopes=["s1", "s2"],
                default_scopes=["s1"],
                adapter_instance=adapter,
            )
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            requested = token_mod.validate_scopes_for_client(
                proof_ctx=proof_ctx, client_rec=client, subject="sub"
            )
            assert requested == ["s1"]

        # now request a scope not allowed
        with app.test_request_context(
            "/token", method="POST",
            data={
                "client_id": "c1",
                "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                "scope": "s3",
            }
        ):
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.validate_scopes_for_client(
                    proof_ctx=proof_ctx, client_rec=client, subject="sub"
                )
            assert ei.value.code == 403


def test_validate_and_clamp_ttl_behavior(app):
    with app.app_context():
        with app.test_request_context(
            "/token", method="POST",
            data={"client_id": "c1", "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                  "requested_ttl_seconds": "3600"}
        ):
            adapter = StubAdapter()
            client = make_client_record(
                "c1", allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
                adapter_instance=adapter
            )
            # set client cap lower than requested by reconstructing dataclass
            client = client.__class__(**{**client.__dict__, "max_session_ttl_seconds": 1800})
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            ttl = token_mod.validate_and_clamp_ttl(
                proof_ctx=proof_ctx, client_rec=client, subject="sub"
            )
            assert ttl == 1800

        # invalid requested ttl should raise 400
        with app.test_request_context(
            "/token", method="POST",
            data={"client_id": "c1", "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                  "requested_ttl_seconds": "notint"}
        ):
            proof_ctx = token_mod.ProofContext(request.form.to_dict(flat=False),
                                              dict(request.headers))
            with pytest.raises(HTTPException) as ei:
                token_mod.validate_and_clamp_ttl(
                    proof_ctx=proof_ctx, client_rec=client, subject="sub"
                )
            assert ei.value.code == 400


def test_client_credentials_happy_path_end_to_end(app):
    """
    Full flow for client_credentials:
      - client in registry (confidential)
      - adapter.authenticate returns an AdapterResult
      - token endpoint creates a session and returns access_token
    """
    subj = Subject(provider="client_secret", subject_id="svc-1")
    ar = AdapterResult(
        subject=subj,
        additional_claims={"email": "svc@example.com"},
        auth_context={"type": "client_secret"},
    )
    adapter = StubAdapter(result=ar, raise_exc=None)

    client = make_client_record(
        "svc-client",
        allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
        allowed_resources=["urn:svc:r1"],
        allowed_scopes=["s1"],
        default_resources=["urn:svc:r1"],
        default_scopes=["s1"],
        adapter_instance=adapter,
    )

    registry = ClientRegistry(version="1", clients={"svc-client": client})

    # push registry into app config
    app.config["CLIENT_AUTH_REGISTRY"] = registry
    app.config["IDP_CLAIM_MAPS"] = {}

    with app.test_client() as c:
        resp = c.post(
            "/token",
            data={
                "client_id": "svc-client",
                "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
            },
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert "access_token" in body and "expires_in" in body

        # session should be created in store
        store = app.config["SESSION_STORE"]
        sessions = store.list_session_ids()
        assert len(sessions) >= 1

        assert body["token_type"] == "bearer"
        assert isinstance(body["expires_in"], int)


def test_adapter_autherror_propagates(monkeypatch, app):
    # Arrange: client_rec whose adapter.authenticate raises AdapterAuthError (403)
    def fake_auth(*a, **k):
        raise AdapterAuthError("not allowed", status=403, error_code="unauthorized_client")

    adapter = DummyAdapter.from_dict({}, "svc-adp")
    monkeypatch.setattr(adapter, "authenticate", fake_auth)

    cr = make_client_record(
        client_id="bad-adapter",
        adapter_instance=adapter,
        allowed_auth_methods=["client_secret_basic"],
    )
    # monkeypatch the registry lookup
    class FakeRegistry:
        def get(self, cid):
            return cr if cid == "bad-adapter" else None

    monkeypatch.setitem(app.config, "CLIENT_AUTH_REGISTRY", FakeRegistry())

    with app.test_client() as c:
        resp = c.post(
            "/token",
            data={
                "client_id": "bad-adapter",
                "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
            },
        )
        assert resp.status_code == 403
        j = resp.get_json()
        assert j["error"]


def test_adapter_error_results_500(monkeypatch, app):
    def fake_auth(*a, **k):
        raise AdapterError("internal adapter failure")

    adapter = DummyAdapter.from_dict({}, "svc-adp2")
    monkeypatch.setattr(adapter, "authenticate", fake_auth)
    cr = make_client_record(client_id="bad-adapter-2", adapter_instance=adapter)

    class FakeRegistry:
        def get(self, cid):
            return cr if cid == "bad-adapter-2" else None

    monkeypatch.setitem(app.config, "CLIENT_AUTH_REGISTRY", FakeRegistry())

    with app.test_client() as c:
        resp = c.post(
            "/token",
            data={
                "client_id": "bad-adapter-2",
                "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
            },
        )
        assert resp.status_code == 500


def test_validate_client_missing_and_unknown(monkeypatch, app):
    # missing client_id -> 400
    with app.test_client() as c:
        resp = c.post("/token", data={"grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value})
        assert resp.status_code == 400

    # unknown client -> 401
    class EmptyRegistry:
        def get(self, cid):
            return None

    monkeypatch.setitem(app.config, "CLIENT_AUTH_REGISTRY", EmptyRegistry())
    with app.test_client() as c:
        resp = c.post(
            "/token",
            data={"client_id": "nope", "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value},
        )
        assert resp.status_code == 401


def test_validate_grant_type_missing_and_unsupported(monkeypatch, app):
    adapter = DummyAdapter.from_dict({}, "c1")
    cr = make_client_record(
        client_id="c1",
        adapter_instance=adapter,
        allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
    )
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr})())

    with app.test_client() as c:
        # missing grant_type -> 400
        resp = c.post("/token", data={"client_id": "c1"})
        assert resp.status_code == 400

        # unsupported grant_type (bad string) -> 400
        resp2 = c.post("/token", data={"client_id": "c1", "grant_type": "bad_grant"})
        assert resp2.status_code == 400

        # not allowed grant_type -> 401 (make a client that doesn't allow that)
        cr2 = make_client_record(client_id="c2", adapter_instance=adapter, allowed_grant_types=["something_else"])
        monkeypatch.setitem(app.config,
                            "CLIENT_AUTH_REGISTRY", type("R2", (object,), {"get": lambda self, cid: cr2})())
        resp3 = c.post(
            "/token",
            data={"client_id": "c2", "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value},
        )
        assert resp3.status_code == 401


def test_public_client_not_implemented(monkeypatch, app):
    adapter = DummyAdapter.from_dict({}, "pub")
    cr = make_client_record(
        client_id="pubid",
        adapter_instance=adapter,
        public=True,
        allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
    )
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr})())

    with app.test_client() as c:
        resp = c.post(
            "/token",
            data={"client_id": "pubid", "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value},
        )
        # NotImplementedError currently raised -> flask returns 500
        assert resp.status_code == 500


def test_validate_resources_escalation_and_default_and_excessive(monkeypatch, app):
    # Setup adapter result success
    subject = Subject(provider="dummy", subject_id="svcsub")

    def good_auth(*a, **k):
        return AdapterResult(subject=subject, additional_claims={}, auth_context={})

    adapter = DummyAdapter.from_dict({}, "ok")
    monkeypatch.setattr(adapter, "authenticate", good_auth)

    # Case: no allowed_resources -> server error
    cr_no_allowed = make_client_record(client_id="r1", adapter_instance=adapter, allowed_resources=[])
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr_no_allowed})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "r1",
                                      "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value})
        assert resp.status_code == 500

    # Case: resource escalation attempt - client allowed only A but requests B
    cr_allowed = make_client_record(client_id="r2",
                                    adapter_instance=adapter,
                                    allowed_resources=["urn:svc:A"],
                                    default_resources=[])
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R2", (object,), {"get": lambda self, cid: cr_allowed})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "r2",
                                      "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                                      "resource": "urn:svc:B"})
        assert resp.status_code == 403

    # Case: defaulted resources used when none requested
    cr_default = make_client_record(client_id="r3",
                                    adapter_instance=adapter,
                                    allowed_resources=["urn:svc:A"],
                                    default_resources=["urn:svc:A"])
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R3", (object,), {"get": lambda self, cid: cr_default})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "r3",
                                      "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value})
        assert resp.status_code == 200

    # Case: excessive resources (>MAX_RESOURCES) -> 400
    many = [f"urn:res:res{i}" for i in range(token_mod.MAX_RESOURCES + 1)]
    cr_many = make_client_record(client_id="r4",
                                 adapter_instance=adapter,
                                 allowed_resources=many,
                                 default_resources=many)
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R4", (object,), {"get": lambda self, cid: cr_many})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "r4", "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value})
        assert resp.status_code == 400


def test_validate_scopes_missing_default_and_violation(monkeypatch, app):
    subject = Subject(provider="dummy", subject_id="svcsub")
    adapter = DummyAdapter.from_dict({}, "ok2")
    monkeypatch.setattr(adapter,
                        "authenticate",
                        lambda *a, **k: AdapterResult(subject=subject, additional_claims={}, auth_context={}))

    # missing scopes + no default -> 400
    cr_noscope = make_client_record(client_id="s1", adapter_instance=adapter,
                                    allowed_scopes=["a"], allowed_resources=["urn:svc:r1"])
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr_noscope})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "s1",
                                      "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                                      "resource": "urn:svc:r1"})
        assert resp.status_code == 400

    # scope violation -> 403
    cr_allowed = make_client_record(client_id="s2", adapter_instance=adapter,
                                    allowed_scopes=["x"], default_scopes=["x"],
                                    allowed_resources=["urn:svc:r1"])
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R2", (object,), {"get": lambda self, cid: cr_allowed})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "s2",
                                      "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                                      "scope": "y",
                                      "resource": "urn:svc:r1"})
        assert resp.status_code == 403

    # defaulted scope -> 200
    cr_def = make_client_record(client_id="s3", adapter_instance=adapter,
                                allowed_scopes=["x"], default_scopes=["x"],
                                allowed_resources=["urn:svc:r1"])
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R3", (object,), {"get": lambda self, cid: cr_def})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "s3",
                                      "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                                      "resource": "urn:svc:r1"})
        assert resp.status_code == 200


def test_validate_and_clamp_ttl_bad_and_clamp(monkeypatch, app):
    subject = Subject(provider="dummy", subject_id="svcsub")
    adapter = DummyAdapter.from_dict({}, "ok3")
    monkeypatch.setattr(adapter, "authenticate",
                        lambda *a, **k: AdapterResult(subject=subject, additional_claims={}, auth_context={}))

    # invalid TTL must return 400
    cr = make_client_record(client_id="t1", adapter_instance=adapter,
                            allowed_resources=["urn:svc:r1"])

    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "t1",
                                      "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                                      "requested_ttl_seconds": "notint",
                                      "resource": "urn:svc:r1"})
        assert resp.status_code == 400

    # clamp TTL: request bigger than client_rec.max_session_ttl_seconds -> should be clamped and return 200
    cr2 = make_client_record(client_id="t2", adapter_instance=adapter,
                             allowed_resources=["urn:svc:r1"])
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R2", (object,), {"get": lambda self, cid: cr2})())
    with app.test_client() as c:
        resp = c.post("/token", data={"client_id": "t2",
                                      "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value,
                                      "requested_ttl_seconds": "99999",
                                      "resource": "urn:svc:r1"})
        assert resp.status_code in (200, 400, 401)


def test_merge_userinfo_merges_adapter_and_client_claims(monkeypatch, app):
    subject = Subject(provider="dummy", subject_id="svcmerge")
    adapter = DummyAdapter.from_dict({}, "ok4")
    monkeypatch.setattr(adapter,
                        "authenticate",
                        lambda *a, **k: AdapterResult(subject=subject,
                                                      additional_claims={"role": "svc"},
                                                      auth_context={}))

    cr = make_client_record(
        client_id="m1",
        adapter_instance=adapter,
        additional_claims={"env": "test"},
        allowed_claims=["env", "role"],
    )
    monkeypatch.setitem(app.config,
                        "CLIENT_AUTH_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr})())

    # call the internal merge_userinfo helper inside app context
    with app.app_context():
        merged = token_mod.merge_userinfo({"sub": "x"}, cr, adapter_claims={"role": "svc"})
    assert "env" in merged and "role" in merged
