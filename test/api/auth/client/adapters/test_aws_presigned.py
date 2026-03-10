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
import requests
from dataclasses import dataclass
from typing import Dict, Optional
from credenza.api.common.errors import OAuthError
from credenza.api.auth.client.adapters.impl import aws_presigned as aws_mod
from credenza.api.auth.client.adapters.impl.aws_presigned import AwsPresignedAdapter
from credenza.api.auth.client.adapters.adapter import ProofContext, AdapterResult, AdapterError, AdapterAuthError


@dataclass
class DummyResp:
    status_code: int
    text: str
    headers: Dict[str, str]
    url: str = ""

    def close(self):
        pass


class DummySession:
    def __init__(self, resp: DummyResp, exc: Optional[Exception] = None):
        # if exc is provided, .get will raise it
        self._resp = resp
        self._exc = exc
        self.closed = False

    def get(self, url, timeout):
        if self._exc:
            raise self._exc
        return self._resp

    def close(self):
        self.closed = True


def dummy_retrying_requests_session_factory(resp: DummyResp, exc: Optional[Exception] = None):
    # returns a callable that mirrors the signature used in production:
    # retrying_requests_session(total=..., backoff_factor=...) -> session
    def _factory(*args, **kwargs):
        return DummySession(resp, exc=exc)
    return _factory


def make_adapter(role_arn: str) -> AwsPresignedAdapter:
    # returns an instantiated adapter via from_dict
    return AwsPresignedAdapter.from_dict({"role_arn": role_arn}, client_id="c1")


def make_ctx(presigned_url: str = "", resource: Optional[str] = None):
    form = {}
    if presigned_url:
        form["presigned_url"] = presigned_url
    if resource:
        form["resource"] = resource
    return ProofContext(form=form, headers={}, client_ip="1.2.3.4", request_id="rid")


@pytest.fixture(autouse=True)
def patch_default_retry(monkeypatch):
    # Patch the symbol inside the aws_presigned module (where the adapter actually looks it up)
    monkeypatch.setattr(aws_mod, "retrying_requests_session",
                        dummy_retrying_requests_session_factory(DummyResp(200, "", {})),
                        raising=True)
    yield


def test_from_dict_requires_role_arn():
    with pytest.raises(ValueError, match="role_arn required"):
        AwsPresignedAdapter.from_dict({}, client_id="cid")


def test_extract_iam_role_identity_various_shapes_and_nonstring():
    a = make_adapter("arn:aws:sts::111111111111:assumed-role/role/session")

    # assumed-role format
    assert a._extract_iam_role_identity("arn:aws:sts::111111111111:assumed-role/role/session") == ("111111111111", "role")

    # iam role with path
    assert a._extract_iam_role_identity("arn:aws:iam::222222222222:role/path/sub/roleName") == ("222222222222", "roleName")

    # non-string input
    assert a._extract_iam_role_identity(None) is None
    assert a._extract_iam_role_identity(123) is None


def test_extract_arn_from_xml_and_parse_error():
    a = make_adapter("arn:aws:sts::111111111111:assumed-role/role/session")
    good_xml = "<Root><Something><Arn>arn:aws:sts::111111111111:assumed-role/role/session</Arn></Something></Root>"
    assert a._extract_arn_from_xml(good_xml) == "arn:aws:sts::111111111111:assumed-role/role/session"

    # invalid xml -> returns None
    assert a._extract_arn_from_xml("<<<not-xml>>>") is None


def test_extract_error_from_xml_parses_code_and_message_and_parse_error():
    a = make_adapter("arn:aws:sts::111111111111:assumed-role/role/session")
    xml = "<Error><Code>AccessDenied</Code><Message>Denied</Message></Error>"
    code, msg = a._extract_error_from_xml(xml)
    assert code == "AccessDenied"
    assert msg == "Denied"

    # parse error returns (None, None)
    c, m = a._extract_error_from_xml("not-xml")
    assert c is None and m is None


def test_get_caller_identity_success_parses_xml_and_regex_fallback(monkeypatch):
    role = "arn:aws:sts::333333333333:assumed-role/role/session"
    a = make_adapter(role)

    # Case1: xml <Arn> element
    xml_ok = "<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:sts::333333333333:assumed-role/role/session</Arn></GetCallerIdentityResult></GetCallerIdentityResponse>"
    resp1 = DummyResp(status_code=200, text=xml_ok, headers={}, url="https://sts.amazonaws.com/?Action=GetCallerIdentity")

    # Patch the retrying_requests_session symbol inside aws_presigned module using the factory
    monkeypatch.setattr(aws_mod, "retrying_requests_session",
                        dummy_retrying_requests_session_factory(resp1),
                        raising=True)

    ctx = make_ctx("https://sts.amazonaws.com/?Action=GetCallerIdentity")
    arn1, r1, status1 = a._get_caller_identity_via_presigned(ctx, "https://sts.amazonaws.com/?Action=GetCallerIdentity")
    assert arn1 == "arn:aws:sts::333333333333:assumed-role/role/session"
    assert status1 == 200

    # Case2: no <Arn> but ARN present in body -> regex fallback
    # NOTE: fallback regex expects a non-empty region segment, so include a region here.
    body_with_arn = "prefix arn:aws:sts:us-east-1:333333333333:assumed-role/role/session suffix"
    resp2 = DummyResp(status_code=200, text=body_with_arn, headers={}, url="https://sts.amazonaws.com/?Action=GetCallerIdentity")
    monkeypatch.setattr(aws_mod, "retrying_requests_session",
                        dummy_retrying_requests_session_factory(resp2),
                        raising=True)

    ctx2 = make_ctx("https://sts.amazonaws.com/?Action=GetCallerIdentity")
    arn2, r2, status2 = a._get_caller_identity_via_presigned(ctx2, "https://sts.amazonaws.com/?Action=GetCallerIdentity")
    assert "arn:aws:sts:us-east-1:333333333333:assumed-role/role/session" in arn2
    assert status2 == 200


def test_get_caller_identity_timeout_and_request_exception(monkeypatch):
    role = "arn:aws:sts::333333333333:assumed-role/role/session"
    a = make_adapter(role)

    # Timeout path -> AdapterError
    monkeypatch.setattr(aws_mod, "retrying_requests_session",
                        dummy_retrying_requests_session_factory(DummyResp(200, "", {}), exc=requests.Timeout()),
                        raising=True)
    with pytest.raises(AdapterError, match="timeout"):
        a._get_caller_identity_via_presigned(ProofContext(form={}, headers={}), "https://sts.amazonaws.com/?Action=GetCallerIdentity")

    # RequestException path -> AdapterError
    monkeypatch.setattr(aws_mod, "retrying_requests_session",
                        dummy_retrying_requests_session_factory(DummyResp(200, "", {}), exc=requests.RequestException("fail")),
                        raising=True)
    with pytest.raises(AdapterError, match="error calling presigned URL"):
        a._get_caller_identity_via_presigned(ProofContext(form={}, headers={}), "https://sts.amazonaws.com/?Action=GetCallerIdentity")


def test_get_caller_identity_http_4xx_and_5xx(monkeypatch):
    role = "arn:aws:sts::444444444444:assumed-role/role/session"
    a = make_adapter(role)

    # 4xx -> AdapterAuthError with INVALID_TOKEN code
    resp_4xx = DummyResp(status_code=401,
                        text="<Error><Code>TokenInvalid</Code><Message>bad</Message></Error>",
                        headers={"x-amzn-RequestId": "RID"},
                        url="https://sts.amazonaws.com/")
    monkeypatch.setattr(aws_mod, "retrying_requests_session",
                        dummy_retrying_requests_session_factory(resp_4xx),
                        raising=True)
    with pytest.raises(AdapterAuthError) as ei:
        a._get_caller_identity_via_presigned(ProofContext(form={}, headers={}), "https://sts.amazonaws.com/?Action=GetCallerIdentity")
    assert ei.value.status == 401
    assert ei.value.error_code == OAuthError.INVALID_TOKEN.code

    # 5xx -> AdapterError
    resp_5xx = DummyResp(status_code=503, text="<Error><Code>Service</Code></Error>", headers={}, url="https://sts.amazonaws.com/")
    monkeypatch.setattr(aws_mod, "retrying_requests_session",
                        dummy_retrying_requests_session_factory(resp_5xx),
                        raising=True)
    with pytest.raises(AdapterError, match="presigned URL returned error status 503"):
        a._get_caller_identity_via_presigned(ProofContext(form={}, headers={}), "https://sts.amazonaws.com/?Action=GetCallerIdentity")


def test_get_caller_identity_missing_arn_in_body_raises_auth_error(monkeypatch):
    role = "arn:aws:sts::555555555555:assumed-role/role/session"
    a = make_adapter(role)

    # 200 but body lacks ARN -> should raise AdapterAuthError
    resp_no_arn = DummyResp(status_code=200, text="no arn here", headers={}, url="https://sts.amazonaws.com/")
    monkeypatch.setattr(aws_mod, "retrying_requests_session",
                        dummy_retrying_requests_session_factory(resp_no_arn),
                        raising=True)
    with pytest.raises(AdapterAuthError) as ei:
        a._get_caller_identity_via_presigned(ProofContext(form={}, headers={}), "https://sts.amazonaws.com/?Action=GetCallerIdentity")
    assert ei.value.error_code == OAuthError.INVALID_TOKEN.code


def test_authenticate_invalid_ctx_and_missing_url_and_malformed_and_method_not_allowed(monkeypatch):
    role = "arn:aws:sts::666666666666:assumed-role/role/session"
    a = make_adapter(role)

    # invalid ctx (None)
    with pytest.raises(AdapterError):
        a.authenticate(None)  # type: ignore[arg-type]

    # missing url -> AdapterAuthError INVALID_REQUEST
    with pytest.raises(AdapterAuthError) as ei:
        a.authenticate(ProofContext(form={}, headers={}))
    assert ei.value.error_code == OAuthError.INVALID_REQUEST.code

    # method not allowed: allowed_methods doesn't include the adapter's detected method
    ctx = make_ctx("https://sts.amazonaws.com/?Action=GetCallerIdentity")
    # patch instance method to return a valid arn so authenticate reaches allowed method logic
    monkeypatch.setattr(a, "_get_caller_identity_via_presigned",
                        lambda ctx_arg, url, timeout=(2.0, 3.0): (role, DummyResp(200, "", {}), 200),
                        raising=True)
    with pytest.raises(AdapterAuthError) as ei2:
        a.authenticate(ctx, allowed_methods=["some_other_method"])
    assert ei2.value.status == 403
    assert ei2.value.error_code == OAuthError.UNAUTHORIZED_CLIENT.code

    # malformed presigned URL (no getcalleridentity) -> INVALID_REQUEST
    with pytest.raises(AdapterAuthError) as ei3:
        a.authenticate(make_ctx("https://example.com/"))
    assert ei3.value.error_code == OAuthError.INVALID_REQUEST.code


def test_authenticate_unrecognized_and_config_mismatch_and_success(monkeypatch):
    # This covers three authenticate paths using instance-level patches:
    configured_role = "arn:aws:sts::222222222222:assumed-role/configuredRole/session"
    a = make_adapter(configured_role)

    resp_ok = DummyResp(status_code=200, text="<Root><Arn>arn:aws:sts::222222222222:assumed-role/configuredRole/session</Arn></Root>", headers={})
    resp_unrec = DummyResp(status_code=200, text="no-arn-here", headers={})
    resp_mismatch = DummyResp(status_code=200, text="<Root><Arn>arn:aws:sts::222222222222:assumed-role/otherrole/session</Arn></Root>", headers={})

    # 1) Unrecognized caller ARN -> AdapterAuthError
    monkeypatch.setattr(a, "_get_caller_identity_via_presigned",
                        lambda ctx_arg, url, timeout=(2.0, 3.0): ("not-an-arn", resp_unrec, 200),
                        raising=True)
    with pytest.raises(AdapterAuthError):
        a.authenticate(make_ctx("https://sts.amazonaws.com/?Action=GetCallerIdentity"))

    # 2) Recognized ARN but mismatch with configured role -> AdapterAuthError ACCESS_DENIED
    monkeypatch.setattr(a, "_get_caller_identity_via_presigned",
                        lambda ctx_arg, url, timeout=(2.0, 3.0): ("arn:aws:sts::222222222222:assumed-role/otherrole/session", resp_mismatch, 200),
                        raising=True)
    with pytest.raises(AdapterAuthError):
        a.authenticate(make_ctx("https://sts.amazonaws.com/?Action=GetCallerIdentity"))

    # 3) Success path
    monkeypatch.setattr(a, "_get_caller_identity_via_presigned",
                        lambda ctx_arg, url, timeout=(2.0, 3.0): ("arn:aws:sts::222222222222:assumed-role/configuredRole/session", resp_ok, 200),
                        raising=True)
    res = a.authenticate(make_ctx("https://sts.amazonaws.com/?Action=GetCallerIdentity", resource="r1"))
    assert isinstance(res, AdapterResult)
    assert res.subject.provider == "aws"


def test_authenticate_subject_creation_failure(monkeypatch):
    # Subject() construction raising should be wrapped as AdapterError
    role = "arn:aws:sts::777777777777:assumed-role/role/session"
    a = make_adapter(role)

    # normal successful remote identity retrieval
    monkeypatch.setattr(a, "_get_caller_identity_via_presigned",
                        lambda ctx_arg, url, timeout=(2.0, 3.0): (role, DummyResp(200, "", {}), 200),
                        raising=True)

    # monkeypatch Subject in the aws_presigned module to raise on init
    orig_subject = aws_mod.Subject
    try:
        class FakeSubject:
            def __init__(self, provider, subject_id):
                raise RuntimeError("boom")

        monkeypatch.setattr(aws_mod, "Subject", FakeSubject, raising=True)

        with pytest.raises(AdapterError):
            a.authenticate(make_ctx("https://sts.amazonaws.com/?Action=GetCallerIdentity"))
    finally:
        # restore Subject
        monkeypatch.setattr(aws_mod, "Subject", orig_subject, raising=True)
