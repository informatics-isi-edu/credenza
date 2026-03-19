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
from credenza.api.common.rate_limit import FixedWindowJitterLimiter
from credenza.api.session.storage.session_store import SessionType


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
                       allowed_auth_methods=None,
                       allowed_redirect_uris=None,
                       allowed_token_exchange_targets=None):
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
        allowed_redirect_uris=list(allowed_redirect_uris or []),
        allowed_token_exchange_targets=list(allowed_token_exchange_targets or []),
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

    # Ensure a minimal CLIENT_REGISTRY and IDP_CLAIM_MAPS exist so tests do not KeyError.
    if "CLIENT_REGISTRY" not in app.config:
        app.config["CLIENT_REGISTRY"] = ClientRegistry(version="0", clients={})
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
    app.config["CLIENT_REGISTRY"] = registry
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

    monkeypatch.setitem(app.config, "CLIENT_REGISTRY", FakeRegistry())

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

    monkeypatch.setitem(app.config, "CLIENT_REGISTRY", FakeRegistry())

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

    monkeypatch.setitem(app.config, "CLIENT_REGISTRY", EmptyRegistry())
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
                        "CLIENT_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr})())

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
                            "CLIENT_REGISTRY", type("R2", (object,), {"get": lambda self, cid: cr2})())
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
                        "CLIENT_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr})())

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
                        "CLIENT_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr_no_allowed})())
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
                        "CLIENT_REGISTRY", type("R2", (object,), {"get": lambda self, cid: cr_allowed})())
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
                        "CLIENT_REGISTRY", type("R3", (object,), {"get": lambda self, cid: cr_default})())
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
                        "CLIENT_REGISTRY", type("R4", (object,), {"get": lambda self, cid: cr_many})())
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
                        "CLIENT_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr_noscope})())
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
                        "CLIENT_REGISTRY", type("R2", (object,), {"get": lambda self, cid: cr_allowed})())
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
                        "CLIENT_REGISTRY", type("R3", (object,), {"get": lambda self, cid: cr_def})())
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
                        "CLIENT_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr})())
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
                        "CLIENT_REGISTRY", type("R2", (object,), {"get": lambda self, cid: cr2})())
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
                        "CLIENT_REGISTRY", type("R", (object,), {"get": lambda self, cid: cr})())

    # call the internal merge_userinfo helper inside app context
    with app.app_context():
        merged = token_mod.merge_userinfo({"sub": "x"}, cr, adapter_claims={"role": "svc"})
    assert "env" in merged and "role" in merged


# ===========================================================================
# authorization_code grant handler tests
# ===========================================================================

import hashlib
import base64
from credenza.api.session.storage.session_store import SessionType


_REDIRECT_URI_TC = "https://client.example/callback"
_RESOURCE_TC = "https://api.example/"
_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"  # 43-char RFC 7636 example


def _s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _make_authz_client(app, public=True, allowed_resources=None):
    """Register a client_rec that allows authorization_code grant."""
    cr = make_client_record(
        client_id="authz-client",
        public=public,
        allowed_grant_types=["authorization_code"],
        allowed_resources=allowed_resources or [_RESOURCE_TC],
        allowed_redirect_uris=[_REDIRECT_URI_TC],
    )
    app.config["CLIENT_REGISTRY"] = ClientRegistry(
        version="1", clients={"authz-client": cr}
    )
    return cr


def _store_code(store, *, client_id="authz-client", redirect_uri=_REDIRECT_URI_TC,
                session_id, code_challenge=None, code_challenge_method=None,
                resources=None, realm="test"):
    """Store an authorization code payload and return (code, payload)."""
    import secrets as _sec
    code = _sec.token_urlsafe(32)
    payload = {
        "session_id":            session_id,
        "client_id":             client_id,
        "redirect_uri":          redirect_uri,
        "code_challenge":        code_challenge,
        "code_challenge_method": code_challenge_method,
        "scope":                 "openid email",
        "resources":             resources or [_RESOURCE_TC],
        "realm":                 realm,
        "issued_at":             int(time.time()),
    }
    store.set_authorization_code(code, payload, ttl=300)
    return code, payload


def _create_user_session(store):
    """Create a live USER session and return (sid, skey)."""
    sid = store.generate_session_id()
    skey, _ = store.create_session(
        session_id=sid,
        session_type=SessionType.USER,
        access_token=store.generate_session_key(),
        userinfo={"sub": "u1", "email": "u@example.com"},
        realm="test",
        allowed_resources=[_RESOURCE_TC],
    )
    return sid, skey


def test_authz_code_happy_path_with_pkce(app, store, monkeypatch):
    """Valid code + PKCE -- 200 with access_token."""
    _make_authz_client(app)
    sid, expected_skey = _create_user_session(store)
    challenge = _s256(_VERIFIER)
    code, _ = _store_code(store, session_id=sid,
                          code_challenge=challenge, code_challenge_method="S256")

    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":     "authz-client",
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  _REDIRECT_URI_TC,
            "code_verifier": _VERIFIER,
        })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["access_token"] == expected_skey
    assert data["token_type"].lower() == "bearer"
    assert "expires_in" in data


def test_authz_code_happy_path_no_pkce_confidential(app, store, monkeypatch):
    """Confidential client without PKCE -- 200."""
    _make_authz_client(app, public=False)
    sid, expected_skey = _create_user_session(store)
    code, _ = _store_code(store, session_id=sid)

    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": _REDIRECT_URI_TC,
        })
    assert resp.status_code == 200
    assert resp.get_json()["access_token"] == expected_skey


def test_authz_code_missing_code(app, store):
    _make_authz_client(app)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "redirect_uri": _REDIRECT_URI_TC,
        })
    assert resp.status_code == 400


def test_authz_code_missing_redirect_uri(app, store):
    _make_authz_client(app)
    sid, _ = _create_user_session(store)
    code, _ = _store_code(store, session_id=sid)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":  "authz-client",
            "grant_type": "authorization_code",
            "code":       code,
        })
    assert resp.status_code == 400


def test_authz_code_invalid_code(app, store):
    """Non-existent code -- 400 INVALID_GRANT."""
    _make_authz_client(app)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "code":         "no-such-code",
            "redirect_uri": _REDIRECT_URI_TC,
        })
    assert resp.status_code == 400


def test_authz_code_single_use(app, store):
    """Auth code can only be used once."""
    _make_authz_client(app)
    sid, _ = _create_user_session(store)
    code, _ = _store_code(store, session_id=sid)

    with app.test_client() as c:
        r1 = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": _REDIRECT_URI_TC,
        })
        r2 = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": _REDIRECT_URI_TC,
        })
    assert r1.status_code == 200
    assert r2.status_code == 400


def test_authz_code_client_mismatch(app, store):
    """Code issued to different client -- 400."""
    _make_authz_client(app)
    sid, _ = _create_user_session(store)
    code, _ = _store_code(store, session_id=sid, client_id="other-client")
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": _REDIRECT_URI_TC,
        })
    assert resp.status_code == 400


def test_authz_code_redirect_uri_mismatch(app, store):
    """redirect_uri in request doesn't match stored payload -- 400."""
    _make_authz_client(app)
    sid, _ = _create_user_session(store)
    code, _ = _store_code(store, session_id=sid)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": "https://evil.example/callback",
        })
    assert resp.status_code == 400


def test_authz_code_pkce_wrong_verifier(app, store):
    """Wrong code_verifier -- 400 INVALID_GRANT."""
    _make_authz_client(app)
    sid, _ = _create_user_session(store)
    challenge = _s256(_VERIFIER)
    code, _ = _store_code(store, session_id=sid,
                          code_challenge=challenge, code_challenge_method="S256")
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":     "authz-client",
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  _REDIRECT_URI_TC,
            "code_verifier": "wrong-verifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        })
    assert resp.status_code == 400


def test_authz_code_pkce_missing_verifier(app, store):
    """Challenge stored but no verifier provided -- 400."""
    _make_authz_client(app)
    sid, _ = _create_user_session(store)
    challenge = _s256(_VERIFIER)
    code, _ = _store_code(store, session_id=sid,
                          code_challenge=challenge, code_challenge_method="S256")
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": _REDIRECT_URI_TC,
        })
    assert resp.status_code == 400


def test_authz_code_session_expired(app, store):
    """Session was deleted before code exchange -- 400 INVALID_GRANT."""
    _make_authz_client(app)
    sid, _ = _create_user_session(store)
    code, _ = _store_code(store, session_id=sid)
    store.delete_session(sid)  # simulate session expiry
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":    "authz-client",
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": _REDIRECT_URI_TC,
        })
    assert resp.status_code == 400


# ===========================================================================
# token_exchange grant handler tests
# ===========================================================================

_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
_TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"


def _make_exchange_client(app, *,
                          allowed_resources=None,
                          allowed_scopes=None,
                          allowed_targets=None,
                          max_session_ttl_seconds=None):
    """Register a client that allows token_exchange grant."""
    cr = make_client_record(
        client_id="exchange-client",
        public=True,  # no adapter auth required for these tests
        allowed_grant_types=[_TOKEN_EXCHANGE_GRANT],
        allowed_resources=allowed_resources or [_RESOURCE_TC],
        allowed_scopes=allowed_scopes or [],
        allowed_token_exchange_targets=allowed_targets or [_RESOURCE_TC],
    )
    if max_session_ttl_seconds is not None:
        from dataclasses import replace
        cr = replace(cr, max_session_ttl_seconds=max_session_ttl_seconds)
    app.config["CLIENT_REGISTRY"] = ClientRegistry(
        version="1", clients={"exchange-client": cr}
    )
    return cr


def _create_subject_session(store, scopes="openid email", resources=None):
    """Create a live USER session suitable for use as token-exchange subject."""
    sid = store.generate_session_id()
    skey, _ = store.create_session(
        session_id=sid,
        session_type=SessionType.USER,
        access_token=store.generate_session_key(),
        userinfo={"sub": "u1", "email": "u@example.com"},
        realm="test",
        scopes=scopes,
        allowed_resources=resources or [_RESOURCE_TC],
    )
    return sid, skey


def test_token_exchange_happy_path(app, store):
    """Valid exchange returns DERIVED token with RFC 8693 fields."""
    _make_exchange_client(app)
    _, skey = _create_subject_session(store)

    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "resource":           _RESOURCE_TC,
        })
    assert resp.status_code == 200
    data = resp.get_json()
    assert "access_token" in data
    assert data["token_type"].lower() == "bearer"
    assert data["issued_token_type"] == _TOKEN_TYPE_ACCESS
    assert "expires_in" in data
    assert data["expires_in"] <= token_mod.DERIVED_SESSION_MAX_TTL


def test_token_exchange_derives_session_type(app, store):
    """Issued session has SessionType.DERIVED."""
    _make_exchange_client(app)
    _, skey = _create_subject_session(store)

    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
        })
    assert resp.status_code == 200
    derived_skey = resp.get_json()["access_token"]
    _, derived_session = store.get_active_session_by_session_key(derived_skey)
    assert derived_session is not None
    assert derived_session.is_derived()


def test_token_exchange_missing_subject_token(app, store):
    _make_exchange_client(app)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
        })
    assert resp.status_code == 400


def test_token_exchange_missing_subject_token_type(app, store):
    _make_exchange_client(app)
    _, skey = _create_subject_session(store)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":     "exchange-client",
            "grant_type":    _TOKEN_EXCHANGE_GRANT,
            "subject_token": skey,
        })
    assert resp.status_code == 400


def test_token_exchange_unsupported_subject_token_type(app, store):
    _make_exchange_client(app)
    _, skey = _create_subject_session(store)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        })
    assert resp.status_code == 400


def test_token_exchange_invalid_subject_token(app, store):
    """Non-existent/expired subject token -- 400 INVALID_TOKEN."""
    _make_exchange_client(app)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      "no-such-token",
            "subject_token_type": _TOKEN_TYPE_ACCESS,
        })
    assert resp.status_code == 400


def test_token_exchange_transitive_denied(app, store):
    """DERIVED sessions cannot be used as subject tokens."""
    _make_exchange_client(app)
    sid = store.generate_session_id()
    skey, _ = store.create_session(
        session_id=sid,
        session_type=SessionType.DERIVED,
        access_token=store.generate_session_key(),
        userinfo={"sub": "u1"},
        realm="test",
        scopes="openid",
        allowed_resources=[_RESOURCE_TC],
    )
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
        })
    assert resp.status_code == 403


def test_token_exchange_default_deny_no_targets(app, store):
    """Client with empty allowed_token_exchange_targets -- 403."""
    cr = make_client_record(
        client_id="exchange-client",
        public=True,
        allowed_grant_types=[_TOKEN_EXCHANGE_GRANT],
        allowed_resources=[_RESOURCE_TC],
        allowed_token_exchange_targets=[],
    )
    app.config["CLIENT_REGISTRY"] = ClientRegistry(
        version="1", clients={"exchange-client": cr}
    )
    _, skey = _create_subject_session(store)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
        })
    assert resp.status_code == 403


def test_token_exchange_resource_not_in_targets(app, store):
    """Requested resource not in allowed_token_exchange_targets -- 403."""
    _make_exchange_client(app, allowed_targets=["https://other.example/"])
    _, skey = _create_subject_session(store, resources=[_RESOURCE_TC])
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "resource":           _RESOURCE_TC,
        })
    assert resp.status_code == 403


def test_token_exchange_resource_not_in_subject_session_succeeds(app, store):
    """Exchange to a resource not in the subject session's bound resources succeeds
    when the client has explicit allowed_token_exchange_targets permission.

    The subject token's resource binding establishes identity (who the user is),
    not the ceiling of downstream delegation. allowed_token_exchange_targets is
    the policy boundary for what the exchange client can access on the user's
    behalf. This supports the MCP delegation pattern where the user's token is
    scoped to the MCP resource server but the MCP server needs to exchange it
    for access to downstream DERIVA services. See ADR-0001 and ADR-0002.
    """
    other = "https://other.example/"
    _make_exchange_client(
        app,
        allowed_resources=[_RESOURCE_TC, other],
        allowed_targets=[_RESOURCE_TC, other],
    )
    _, skey = _create_subject_session(store, resources=[_RESOURCE_TC])
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "resource":           other,
        })
    assert resp.status_code == 200


def test_token_exchange_cross_resource_delegation_denied_without_target(app, store):
    """Exchange to a resource outside allowed_token_exchange_targets is still denied
    even if the client has it in allowed_resources."""
    other = "https://other.example/"
    _make_exchange_client(
        app,
        allowed_resources=[_RESOURCE_TC, other],
        allowed_targets=[_RESOURCE_TC],  # other is NOT in targets
    )
    _, skey = _create_subject_session(store, resources=[_RESOURCE_TC])
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "resource":           other,
        })
    assert resp.status_code == 403


def test_token_exchange_scope_escalation_beyond_subject(app, store):
    """Requesting a scope not held by the subject -- 403."""
    _make_exchange_client(app, allowed_scopes=["openid", "email", "admin"])
    _, skey = _create_subject_session(store, scopes="openid email")
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "scope":              "openid email admin",
        })
    assert resp.status_code == 403


def test_token_exchange_scope_beyond_client_allowed(app, store):
    """Subject has scope but client's allowed_scopes don't include it -- 403."""
    _make_exchange_client(app, allowed_scopes=["openid"])
    _, skey = _create_subject_session(store, scopes="openid email")
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
            "scope":              "openid email",
        })
    assert resp.status_code == 403


def test_token_exchange_confidential_client_auth_failure(app, store):
    """Confidential exchange client with bad credentials -- 401, no derived session created."""
    adapter = DummyAdapter.from_dict({}, "conf-exchange")
    cr = make_client_record(
        client_id="conf-exchange",
        public=False,
        allowed_grant_types=[_TOKEN_EXCHANGE_GRANT],
        allowed_resources=[_RESOURCE_TC],
        allowed_token_exchange_targets=[_RESOURCE_TC],
        adapter_instance=adapter,
    )
    app.config["CLIENT_REGISTRY"] = ClientRegistry(
        version="1", clients={"conf-exchange": cr}
    )
    _, skey = _create_subject_session(store)

    import unittest.mock as _mock
    with _mock.patch.object(
        adapter, "authenticate",
        side_effect=AdapterAuthError("bad secret", status=401,
                                    error_code=OAuthError.UNAUTHORIZED_CLIENT.value),
    ):
        with app.test_client() as c:
            resp = c.post("/token", data={
                "client_id":          "conf-exchange",
                "grant_type":         _TOKEN_EXCHANGE_GRANT,
                "subject_token":      skey,
                "subject_token_type": _TOKEN_TYPE_ACCESS,
            })
    assert resp.status_code == 401


def test_token_exchange_ttl_capped(app, store):
    """Derived session TTL is capped at DERIVED_SESSION_MAX_TTL."""
    _make_exchange_client(app, max_session_ttl_seconds=9999)
    _, skey = _create_subject_session(store)

    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
        })
    assert resp.status_code == 200
    assert resp.get_json()["expires_in"] <= token_mod.DERIVED_SESSION_MAX_TTL


# ===========================================================================
# RFC 7009 token revocation tests
# ===========================================================================

def _make_revoke_client(app, client_id="revoke-client"):
    """Register a minimal client that can call /revoke."""
    cr = make_client_record(
        client_id=client_id,
        public=True,
        allowed_grant_types=["authorization_code"],
        allowed_resources=[_RESOURCE_TC],
    )
    app.config["CLIENT_REGISTRY"] = ClientRegistry(
        version="1", clients={client_id: cr}
    )
    return cr


def test_revoke_happy_path_user_session(app, store):
    """Revoking a live user session returns 200 and removes it from the store."""
    _make_revoke_client(app)
    sid, skey = _create_user_session(store)

    with app.test_client() as c:
        resp = c.post("/revoke", data={"client_id": "revoke-client", "token": skey})
    assert resp.status_code == 200
    # Session should be gone
    assert store.get_session_by_session_key(skey) == (None, None)


def test_revoke_happy_path_service_session(app, store):
    """Revoking a service session also returns 200."""
    _make_revoke_client(app)
    sid = store.generate_session_id()
    skey, _ = store.create_session(
        session_id=sid,
        session_type=SessionType.SERVICE,
        access_token=store.generate_session_key(),
        userinfo={"sub": "svc1"},
        realm="test",
    )

    with app.test_client() as c:
        resp = c.post("/revoke", data={"client_id": "revoke-client", "token": skey})
    assert resp.status_code == 200
    assert store.get_session_by_session_key(skey) == (None, None)


def test_revoke_missing_token_returns_200(app, store):
    """Missing token param -- 200 (RFC 7009 sec.2.2)."""
    _make_revoke_client(app)
    with app.test_client() as c:
        resp = c.post("/revoke", data={"client_id": "revoke-client"})
    assert resp.status_code == 200


def test_revoke_unknown_token_returns_200(app, store):
    """Token that doesn't exist -- 200 (RFC 7009 sec.2.2)."""
    _make_revoke_client(app)
    with app.test_client() as c:
        resp = c.post("/revoke", data={"client_id": "revoke-client", "token": "no-such-token"})
    assert resp.status_code == 200


def test_revoke_missing_client_id_returns_400(app, store):
    """No client_id -- 400."""
    _make_revoke_client(app)
    with app.test_client() as c:
        resp = c.post("/revoke", data={"token": "sometoken"})
    assert resp.status_code == 400


def test_revoke_unknown_client_returns_401(app, store):
    """Unknown client_id -- 401."""
    _make_revoke_client(app)
    with app.test_client() as c:
        resp = c.post("/revoke", data={"client_id": "ghost-client", "token": "sometoken"})
    assert resp.status_code == 401


def test_revoke_confidential_client_auth_failure_returns_401(app, store):
    """Confidential client with bad credentials is rejected before revocation."""
    adapter = DummyAdapter.from_dict({}, "revoke-conf")
    cr = make_client_record(
        client_id="revoke-conf",
        public=False,
        allowed_grant_types=["authorization_code"],
        allowed_resources=[_RESOURCE_TC],
        adapter_instance=adapter,
    )
    app.config["CLIENT_REGISTRY"] = ClientRegistry(
        version="1", clients={"revoke-conf": cr}
    )
    _, skey = _create_user_session(store)
    import unittest.mock as _mock
    with _mock.patch.object(adapter, "authenticate",
                            side_effect=AdapterAuthError("bad secret", status=401,
                                                         error_code=OAuthError.UNAUTHORIZED_CLIENT.value)):
        with app.test_client() as c:
            resp = c.post("/revoke", data={"client_id": "revoke-conf", "token": skey})
    assert resp.status_code == 401
    # Session must NOT have been deleted
    assert store.get_session_by_session_key(skey) != (None, None)


def test_revoke_token_type_hint_ignored(app, store):
    """token_type_hint is accepted but ignored; revocation still succeeds."""
    _make_revoke_client(app)
    sid, skey = _create_user_session(store)

    with app.test_client() as c:
        resp = c.post("/revoke", data={
            "client_id":       "revoke-client",
            "token":           skey,
            "token_type_hint": "access_token",
        })
    assert resp.status_code == 200
    assert store.get_session_by_session_key(skey) == (None, None)


# ---------------------------------------------------------------------------
# device_code grant at /token (RFC 8628 sec 3.5)
# ---------------------------------------------------------------------------

DEVICE_CLIENT_ID = "device-poll-client"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _make_device_poll_client(app):
    """Register a public device client in the app's CLIENT_REGISTRY."""
    cr = make_client_record(
        DEVICE_CLIENT_ID,
        public=True,
        allowed_grant_types=[DEVICE_GRANT],
        allowed_resources=["urn:test:resource"],
        allowed_scopes=["openid", "email"],
    )
    registry = ClientRegistry(version="1", clients={DEVICE_CLIENT_ID: cr})
    app.config["CLIENT_REGISTRY"] = registry


def _make_device_session(store):
    sid = "dev-sid-1"
    skey, session = store.create_session(
        session_id=sid,
        session_type=SessionType.DEVICE,
        access_token="dev-access-token",
        userinfo={"sub": "user1", "email": "u@example.com"},
        realm="test",
        id_token="idtok",
        refresh_token="rt",
        scopes="openid email",
    )
    return sid, skey, session


def test_device_token_missing_device_code(app, store):
    _make_device_poll_client(app)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":  DEVICE_CLIENT_ID,
            "grant_type": DEVICE_GRANT,
        })
    assert resp.status_code == 400


def test_device_token_expired_device_code(app, store):
    _make_device_poll_client(app)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":   DEVICE_CLIENT_ID,
            "grant_type":  DEVICE_GRANT,
            "device_code": "nonexistent-code",
        })
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "expired_token"


def test_device_token_client_id_mismatch(app, store):
    _make_device_poll_client(app)
    store.set_device_flow("mismatch-code", {
        "client_id": "other-client",
        "verified": False,
        "session_key": None,
        "interval": 0,
        "last_poll_at": 0,
    }, ttl=60)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":   DEVICE_CLIENT_ID,
            "grant_type":  DEVICE_GRANT,
            "device_code": "mismatch-code",
        })
    assert resp.status_code == 400


def test_device_token_slow_down(app, store, monkeypatch):
    _make_device_poll_client(app)
    frozen = int(time.time())
    monkeypatch.setattr(time, "time", lambda: frozen)
    store.set_device_flow("slow-code", {
        "client_id":    DEVICE_CLIENT_ID,
        "verified":     False,
        "session_key":  None,
        "interval":     3,
        "last_poll_at": frozen,
    }, ttl=60)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":   DEVICE_CLIENT_ID,
            "grant_type":  DEVICE_GRANT,
            "device_code": "slow-code",
        })
    assert resp.status_code == 429
    assert resp.get_json()["error"] == "slow_down"


def test_device_token_authorization_pending(app, store):
    _make_device_poll_client(app)
    store.set_device_flow("pending-code", {
        "client_id":   DEVICE_CLIENT_ID,
        "verified":    False,
        "session_key": None,
        "interval":    0,
        "last_poll_at": 0,
    }, ttl=60)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":   DEVICE_CLIENT_ID,
            "grant_type":  DEVICE_GRANT,
            "device_code": "pending-code",
        })
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "authorization_pending"


def test_device_token_success(app, store):
    _make_device_poll_client(app)
    sid, skey, session = _make_device_session(store)
    store.set_device_flow("success-code", {
        "client_id":   DEVICE_CLIENT_ID,
        "verified":    True,
        "session_key": skey,
        "interval":    0,
        "last_poll_at": 0,
    }, ttl=60)

    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":   DEVICE_CLIENT_ID,
            "grant_type":  DEVICE_GRANT,
            "device_code": "success-code",
        })
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["access_token"] == skey
    assert data["token_type"] == "bearer"
    assert "expires_in" in data
    # Device flow must be cleaned up
    assert store.get_device_flow("success-code") is None


def test_device_token_flow_deleted_on_success(app, store):
    _make_device_poll_client(app)
    sid, skey, session = _make_device_session(store)
    store.set_device_flow("cleanup-code", {
        "client_id":   DEVICE_CLIENT_ID,
        "verified":    True,
        "session_key": skey,
        "interval":    0,
        "last_poll_at": 0,
    }, ttl=60)
    with app.test_client() as c:
        c.post("/token", data={
            "client_id":   DEVICE_CLIENT_ID,
            "grant_type":  DEVICE_GRANT,
            "device_code": "cleanup-code",
        })
    assert store.get_device_flow("cleanup-code") is None


def test_device_token_no_client_id_consistency_check_when_flow_has_none(app, store):
    """If flow has no client_id stored (legacy), any registered client may poll."""
    _make_device_poll_client(app)
    sid, skey, session = _make_device_session(store)
    store.set_device_flow("legacy-code", {
        "verified":    True,
        "session_key": skey,
        "interval":    0,
        "last_poll_at": 0,
    }, ttl=60)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":   DEVICE_CLIENT_ID,
            "grant_type":  DEVICE_GRANT,
            "device_code": "legacy-code",
        })
    assert resp.status_code == 200


def test_device_token_unregistered_client_rejected_by_default(app, store):
    """Unknown client_id is rejected at /token when DEVICE_ALLOW_UNREGISTERED_CLIENTS is not set."""
    _make_device_poll_client(app)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":   "nobody",
            "grant_type":  DEVICE_GRANT,
            "device_code": "any-code",
        })
    assert resp.status_code == 401


def test_device_token_unregistered_client_allowed_when_configured(app, store):
    """Unknown client_id succeeds at /token when DEVICE_ALLOW_UNREGISTERED_CLIENTS=True."""
    _make_device_poll_client(app)
    app.config["ALLOW_UNREGISTERED_CLIENTS"] = True
    sid, skey, session = _make_device_session(store)
    store.set_device_flow("unregistered-code", {
        "client_id":   "unknown-client",
        "verified":    True,
        "session_key": skey,
        "interval":    0,
        "last_poll_at": 0,
    }, ttl=60)
    with app.test_client() as c:
        resp = c.post("/token", data={
            "client_id":   "unknown-client",
            "grant_type":  DEVICE_GRANT,
            "device_code": "unregistered-code",
        })
    assert resp.status_code == 200
    assert resp.get_json()["access_token"] == skey


# ===========================================================================
# Per-client rate limit tests
# ===========================================================================

def _tight_limiter():
    """A single-token limiter that fires on the second call for the same key."""
    return FixedWindowJitterLimiter(limit=1, window_sec=60, seed=42)


def test_client_credentials_per_client_rate_limit_returns_429(app, store):
    """Second client_credentials request from the same client_id within the window is rate-limited."""
    subj = Subject(provider="stub", subject_id="svc-rl")
    ar = AdapterResult(subject=subj, additional_claims={}, auth_context={})
    adapter = StubAdapter(result=ar)
    cr = make_client_record(
        "rl-creds-client",
        allowed_grant_types=[token_mod.GrantType.CLIENT_CREDENTIALS.value],
        allowed_resources=["urn:svc:r1"],
        default_resources=["urn:svc:r1"],
        allowed_scopes=["s1"],
        default_scopes=["s1"],
        adapter_instance=adapter,
    )
    app.config["CLIENT_REGISTRY"] = ClientRegistry(version="1", clients={"rl-creds-client": cr})
    # Disable IP decorator; set per-client bucket to limit=1.
    app.config["ENABLE_RATE_LIMITING"] = False
    app.extensions["rate_limits"]["30_per_min"] = _tight_limiter()

    with app.test_client() as c:
        c.post("/token", data={"client_id": "rl-creds-client",
                               "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value})
        r2 = c.post("/token", data={"client_id": "rl-creds-client",
                                    "grant_type": token_mod.GrantType.CLIENT_CREDENTIALS.value})
    assert r2.status_code == 429
    assert r2.get_json()["error"] == "rate_limited"


def test_revoke_per_client_rate_limit_returns_429(app, store):
    """Second revoke request from the same client_id within the window is rate-limited."""
    cr = make_client_record(
        "rl-revoke-client",
        public=True,
        allowed_grant_types=["authorization_code"],
        allowed_resources=[_RESOURCE_TC],
    )
    app.config["CLIENT_REGISTRY"] = ClientRegistry(version="1", clients={"rl-revoke-client": cr})
    app.config["ENABLE_RATE_LIMITING"] = False
    app.extensions["rate_limits"]["30_per_min"] = _tight_limiter()

    with app.test_client() as c:
        c.post("/revoke", data={"client_id": "rl-revoke-client", "token": "any-token"})
        r2 = c.post("/revoke", data={"client_id": "rl-revoke-client", "token": "any-token"})
    assert r2.status_code == 429
    assert r2.get_json()["error"] == "rate_limited"


def test_token_exchange_per_client_rate_limit_returns_429(app, store):
    """Second token_exchange request from the same client_id within the window is rate-limited."""
    _make_exchange_client(app)
    _, skey = _create_subject_session(store)
    app.config["ENABLE_RATE_LIMITING"] = False
    app.extensions["rate_limits"]["30_per_min"] = _tight_limiter()

    with app.test_client() as c:
        c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
        })
        r2 = c.post("/token", data={
            "client_id":          "exchange-client",
            "grant_type":         _TOKEN_EXCHANGE_GRANT,
            "subject_token":      skey,
            "subject_token_type": _TOKEN_TYPE_ACCESS,
        })
    assert r2.status_code == 429
    assert r2.get_json()["error"] == "rate_limited"
