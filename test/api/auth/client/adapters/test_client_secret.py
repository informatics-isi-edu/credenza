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
from __future__ import annotations
import pytest
import base64
from typing import Optional
from credenza.api.common.errors import OAuthError
from credenza.api.auth.client.adapters.impl.client_secret import ClientSecretAdapter
from credenza.api.auth.client.adapters.adapter import (
    ProofContext,
    AdapterResult,
    AdapterAuthError,
    AdapterError,
)


def make_adapter(client_id: str = "cid", secret: Optional[str] = "s3cr3t", secret_hash: Optional[str] = None):
    cfg = {"client_secret": secret, "client_secret_hash": secret_hash}
    return ClientSecretAdapter.from_dict(cfg, client_id=client_id)


def make_basic_header(cid: str, secret: str) -> str:
    raw = f"{cid}:{secret}".encode("utf-8")
    b64 = base64.b64encode(raw).decode("ascii")
    return f"Basic {b64}"


def make_ctx_with_basic(header_value: Optional[str] = None, resource: Optional[str] = None):
    form = {}
    if resource:
        form["resource"] = resource
    headers = {}
    if header_value is not None:
        headers["Authorization"] = header_value
    return ProofContext(form=form, headers=headers, client_ip="1.2.3.4", request_id="rid")


def make_ctx_with_form(client_id: Optional[str] = None, client_secret: Optional[str] = None, resource: Optional[str] = None):
    form = {}
    if client_id is not None:
        form["client_id"] = client_id
    if client_secret is not None:
        form["client_secret"] = client_secret
    if resource is not None:
        form["resource"] = resource
    return ProofContext(form=form, headers={}, client_ip="1.2.3.4", request_id="rid")


def test_from_dict_requires_secret_or_hash():
    with pytest.raises(ValueError, match="client_secret or client_secret_hash required"):
        ClientSecretAdapter.from_dict({}, client_id="cid")


def test_authenticate_missing_credentials_raises_invalid_request():
    a = make_adapter("cid-x", secret="top")
    with pytest.raises(AdapterAuthError) as ei:
        a.authenticate(make_ctx_with_form())  # no creds anywhere
    assert ei.value.error_code == OAuthError.INVALID_REQUEST.code


def test_authenticate_client_id_mismatch():
    a = make_adapter("correct-id", secret="top")

    # supply form creds with wrong client_id
    ctx = make_ctx_with_form(client_id="wrong", client_secret="top")
    with pytest.raises(AdapterAuthError) as ei:
        a.authenticate(ctx)
    assert ei.value.error_code == OAuthError.UNAUTHORIZED_CLIENT.code


def test_authenticate_secret_verification_raises_internal_adapter_error(monkeypatch):
    a = make_adapter("cid-err", secret="s1")

    # patch verify_secret_candidate in the module where the adapter uses it
    monkeypatch.setattr(
        "credenza.api.auth.client.adapters.impl.client_secret.verify_secret_candidate",
        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        raising=True
    )

    ctx = make_ctx_with_basic(make_basic_header("cid-err", "s1"))
    with pytest.raises(AdapterError) as ei:
        a.authenticate(ctx)
    assert "secret verification failed" in str(ei.value)


def test_authenticate_invalid_secret_returns_invalid_token(monkeypatch):
    a = make_adapter("cid-2", secret="right")

    # patch verify_secret_candidate in the adapter module to return False
    monkeypatch.setattr(
        "credenza.api.auth.client.adapters.impl.client_secret.verify_secret_candidate",
        lambda *a, **k: False,
        raising=True
    )

    ctx = make_ctx_with_basic(make_basic_header("cid-2", "wrong"))
    with pytest.raises(AdapterAuthError) as ei:
        a.authenticate(ctx)
    assert ei.value.error_code == OAuthError.INVALID_TOKEN.code


def test_authenticate_success_basic_and_post(monkeypatch):
    a = make_adapter("cid-good", secret="s-good")

    # patch verify to True in the adapter module
    monkeypatch.setattr(
        "credenza.api.auth.client.adapters.impl.client_secret.verify_secret_candidate",
        lambda *a, **k: True,
        raising=True
    )

    # Basic header path
    ctx_basic = make_ctx_with_basic(make_basic_header("cid-good", "s-good"), resource="resA")
    res = a.authenticate(ctx_basic)
    assert isinstance(res, AdapterResult)
    assert res.subject.subject_id == "cid-good"
    assert res.auth_context["method"] == "client_secret_basic"

    # client_secret_post path
    ctx_post = make_ctx_with_form(client_id="cid-good", client_secret="s-good", resource="resB")
    res2 = a.authenticate(ctx_post)
    assert isinstance(res2, AdapterResult)
    assert res2.subject.subject_id == "cid-good"
    assert res2.auth_context["method"] == "client_secret_post"


def test_allowed_methods_behavior_method_not_allowed_and_unknown(monkeypatch):
    a = make_adapter("cid-allow", secret="sX")

    # patch verify to True for reachability (patch adapter module symbol)
    monkeypatch.setattr(
        "credenza.api.auth.client.adapters.impl.client_secret.verify_secret_candidate",
        lambda *a, **k: True,
        raising=True
    )

    # If allowed_methods contains unknown entries and raise_on_unknown True is used by authenticate,
    # validate_allowed_methods will raise ValueError and authenticate should convert that to AdapterError.
    with pytest.raises(AdapterError):
        a.authenticate(make_ctx_with_basic(make_basic_header("cid-allow", "sX")), allowed_methods=["bogus-method"])

    # If allowed_methods is restrictive and does not include the presented method, expect AdapterAuthError.
    # Present Basic, restrict to client_secret_post only.
    with pytest.raises(AdapterAuthError) as ei2:
        a.authenticate(make_ctx_with_basic(make_basic_header("cid-allow", "sX")), allowed_methods=["client_secret_post"])
    assert ei2.value.error_code == OAuthError.UNAUTHORIZED_CLIENT.code
