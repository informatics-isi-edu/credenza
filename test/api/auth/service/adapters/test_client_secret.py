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
import base64
import pytest
from werkzeug.exceptions import HTTPException

from credenza.api.auth.service.adapters import client_secret as cs
from credenza.api.auth.service.adapters.base import ProofContext, DEFAULT_MAX_TTL


def _ctx(*, form=None, headers=None):
    return ProofContext(form=form or {}, headers=headers or {})


def _basic_header(cid: str, sec: str) -> str:
    tok = base64.b64encode(f"{cid}:{sec}".encode("utf-8")).decode("ascii")
    return f"Basic {tok}"


def _abort_code(exc: HTTPException) -> int:
    return getattr(exc, "code", None)


def test_matches_auth_method_client_secret_basic_or_post_true():
    a = cs.ClientSecretAdapter()

    assert a.matches(_ctx(form={"auth_method": "client_secret_basic"})) is True
    assert a.matches(_ctx(form={"auth_method": "client_secret_post"})) is True

    # case-insensitive
    assert a.matches(_ctx(form={"auth_method": "CLIENT_SECRET_POST"})) is True


def test_matches_falls_back_to_basic_authorization_header():
    a = cs.ClientSecretAdapter()

    assert a.matches(_ctx(headers={"Authorization": _basic_header("cid", "sec")})) is True
    assert a.matches(_ctx(headers={"authorization": _basic_header("cid", "sec")})) is True

    # Not basic
    assert a.matches(_ctx(headers={"Authorization": "Bearer abc"})) is False
    assert a.matches(_ctx()) is False


def test_parse_client_secret_post_success():
    a = cs.ClientSecretAdapter()
    cid, sec = a._parse_client_secret_post(_ctx(form={"client_id": "cid1", "client_secret": "s1"}))
    assert cid == "cid1"
    assert sec == "s1"


@pytest.mark.parametrize(
    "form",
    [
        {},  # missing both
        {"client_id": "cid1"},  # missing secret
        {"client_secret": "s1"},  # missing id
        {"client_id": "", "client_secret": "s1"},  # empty id
        {"client_id": "cid1", "client_secret": ""},  # empty secret
    ],
)
def test_parse_client_secret_post_missing_fields_aborts_400(form):
    a = cs.ClientSecretAdapter()
    with pytest.raises(HTTPException) as excinfo:
        a._parse_client_secret_post(_ctx(form=form))
    assert _abort_code(excinfo.value) == 400


def test_parse_basic_success():
    a = cs.ClientSecretAdapter()
    ctx = _ctx(headers={"Authorization": _basic_header("cid1", "s1")})
    cid, sec = a._parse_basic(ctx)
    assert cid == "cid1"
    assert sec == "s1"


def test_parse_basic_strips_client_id():
    a = cs.ClientSecretAdapter()
    # client_id is stripped; secret is preserved verbatim after the colon
    hdr = _basic_header("  cid1  ", "s1")
    cid, sec = a._parse_basic(_ctx(headers={"Authorization": hdr}))
    assert cid == "cid1"
    assert sec == "s1"


@pytest.mark.parametrize(
    "authz",
    [
        None,
        "",
        "Bearer abc",
        "Basic",                   # missing token
        "Basic ",                  # empty token
        "Basic !!!notbase64!!!",   # invalid b64
    ],
)
def test_parse_basic_malformed_aborts_400(authz):
    a = cs.ClientSecretAdapter()
    ctx = _ctx(headers={"Authorization": authz} if authz is not None else {})
    with pytest.raises(HTTPException) as excinfo:
        a._parse_basic(ctx)
    assert _abort_code(excinfo.value) == 400


def test_parse_basic_empty_client_id_aborts_400():
    a = cs.ClientSecretAdapter()
    # Decodes to ":sec" => empty cid
    tok = base64.b64encode(b":sec").decode("ascii")
    ctx = _ctx(headers={"Authorization": f"Basic {tok}"})
    with pytest.raises(HTTPException) as excinfo:
        a._parse_basic(ctx)
    assert _abort_code(excinfo.value) == 400


def test_verify_and_map_client_secret_post_success(monkeypatch):
    a = cs.ClientSecretAdapter()

    # Deterministic issued_at
    monkeypatch.setattr(cs.time, "time", lambda: 1700000000.0)

    cfg = {
        "bindings": [
            {
                "client_id": "cid1",
                "client_secret": "s1",
                "scopes": ["openid", "email"],
                "resources": ["rest-api"],
                "groups": ["g1"],
                "email": "owner@example.org",
                "name": "svc-cid1",
                "default_scopes": ["openid"],
                "max_ttl_seconds": 900,
            }
        ]
    }

    ctx = _ctx(
        form={
            "auth_method": "client_secret_post",
            "client_id": "cid1",
            "client_secret": "s1",
        },
        headers={}
    )

    res = a.verify_and_map(ctx, cfg)

    assert res.subject.provider == "client_secret"
    assert res.subject.subject_id == "cid1"

    assert res.authz.scopes == ["openid", "email"]
    assert res.authz.resources == ["rest-api"]
    assert res.authz.groups == ["g1"]
    assert res.authz.email == "owner@example.org"
    assert res.authz.name == "svc-cid1"

    assert res.proof["type"] == "client_secret"
    assert res.proof["principal"] == "cid1"
    assert res.proof["issued_at"] == 1700000000

    assert res.policy.default_scopes == ["openid"]
    assert res.policy.max_ttl_seconds == 900


def test_verify_and_map_basic_success(monkeypatch):
    a = cs.ClientSecretAdapter()
    monkeypatch.setattr(cs.time, "time", lambda: 1700000000.0)

    cfg = {
        "bindings": [
            {
                "client_id": "cid1",
                "client_secret": "s1",
                "scopes": ["s1"],
                "resources": ["a1"],
            }
        ]
    }

    ctx = _ctx(
        form={"auth_method": "client_secret_basic"},
        headers={"Authorization": _basic_header("cid1", "s1")}
    )

    res = a.verify_and_map(ctx, cfg)
    assert res.subject.provider == "client_secret"
    assert res.subject.subject_id == "cid1"
    assert res.authz.scopes == ["s1"]
    assert res.authz.resources == ["a1"]
    assert res.proof["issued_at"] == 1700000000


def test_verify_and_map_unknown_client_aborts_401():
    a = cs.ClientSecretAdapter()

    cfg = {"bindings": [{"client_id": "cid1", "client_secret": "s1", "scopes": ["s"], "resources": ["a"]}]}

    ctx = _ctx(
        form={"auth_method": "client_secret_post", "client_id": "nope", "client_secret": "s1"},
        headers={}
    )

    with pytest.raises(HTTPException) as excinfo:
        a.verify_and_map(ctx, cfg)
    assert _abort_code(excinfo.value) == 401


def test_verify_and_map_secret_mismatch_aborts_401():
    a = cs.ClientSecretAdapter()

    cfg = {"bindings": [{"client_id": "cid1", "client_secret": "s1", "scopes": ["s"], "resources": ["a"]}]}

    ctx = _ctx(
        form={"auth_method": "client_secret_post", "client_id": "cid1", "client_secret": "WRONG"},
        headers={}
    )

    with pytest.raises(HTTPException) as excinfo:
        a.verify_and_map(ctx, cfg)
    assert _abort_code(excinfo.value) == 401


def test_verify_and_map_defaults_policy_fields_when_missing(monkeypatch):
    """
    If default_scopes/max_ttl_seconds are omitted, adapter should:
      - default_scopes => []
      - max_ttl_seconds => DEFAULT_MAX_TTL
    """
    a = cs.ClientSecretAdapter()
    monkeypatch.setattr(cs.time, "time", lambda: 1700000000.0)

    cfg = {
        "bindings": [
            {
                "client_id": "cid1",
                "client_secret": "s1",
                "scopes": ["s1"],
                "resources": ["a1"],
            }
        ]
    }

    ctx = _ctx(
        headers={"Authorization": _basic_header("cid1", "s1")},
        form={}
    )

    res = a.verify_and_map(ctx, cfg)
    assert res.policy.default_scopes == []
    assert res.policy.max_ttl_seconds == DEFAULT_MAX_TTL
