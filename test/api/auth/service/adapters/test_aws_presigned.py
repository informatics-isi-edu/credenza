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
import requests
from flask import Flask
from werkzeug.exceptions import HTTPException
from credenza.api.auth.service.adapters import aws_presigned as ap
from credenza.api.auth.service.adapters.base import ProofContext, DEFAULT_MAX_TTL


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _SessionOK:
    def __init__(self, resp):
        self._resp = resp
        self.closed = False
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append((url, timeout))
        return self._resp

    def close(self):
        self.closed = True


class _SessionRaises:
    def __init__(self, exc):
        self._exc = exc
        self.closed = False
        self.calls = []

    def get(self, url, timeout=None):
        self.calls.append((url, timeout))
        raise self._exc

    def close(self):
        self.closed = True


def _ctx(subject_token=None):
    form = {}
    if subject_token is not None:
        form["subject_token"] = subject_token
    return ProofContext(form=form, headers={"X-Test": "1"})


def _abort_code(exc: HTTPException) -> int:
    # werkzeug.exceptions.HTTPException has .code
    return getattr(exc, "code", None)


def test_extract_arn_from_xml_success_and_namespace_tolerant():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
      <GetCallerIdentityResult>
        <Arn> arn:aws:sts::123456789012:assumed-role/MyRole/MySession </Arn>
      </GetCallerIdentityResult>
    </GetCallerIdentityResponse>
    """
    arn = ap._extract_arn_from_xml(xml)
    assert arn == "arn:aws:sts::123456789012:assumed-role/MyRole/MySession"


def test_extract_arn_from_xml_missing_or_bad_xml_returns_none():
    assert ap._extract_arn_from_xml("") is None
    assert ap._extract_arn_from_xml("<not-xml") is None
    assert ap._extract_arn_from_xml("<Root><NoArn/></Root>") is None


def test_extract_error_from_xml_success_and_namespace_tolerant():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
    <ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
      <Error>
        <Code> SignatureDoesNotMatch </Code>
        <Message> The request signature we calculated does not match </Message>
      </Error>
    </ErrorResponse>
    """
    code, msg = ap._extract_error_from_xml(xml)

    assert code == "SignatureDoesNotMatch"
    assert msg == "The request signature we calculated does not match"


def test_extract_error_from_xml_missing_or_bad_xml_returns_none_tuple():
    assert ap._extract_error_from_xml("") == (None, None)
    assert ap._extract_error_from_xml("<not-xml") == (None, None)

    xml = "<Root><SomethingElse>nope</SomethingElse></Root>"
    assert ap._extract_error_from_xml(xml) == (None, None)


def test_extract_error_from_xml_partial_error_fields():
    xml_code_only = "<Error><Code>AccessDenied</Code></Error>"
    code, msg = ap._extract_error_from_xml(xml_code_only)
    assert code == "AccessDenied"
    assert msg is None

    xml_msg_only = "<Error><Message>Denied</Message></Error>"
    code, msg = ap._extract_error_from_xml(xml_msg_only)
    assert code is None
    assert msg == "Denied"


def test_derive_role_arn_from_caller_success_and_failure():
    caller = "arn:aws:sts::123456789012:assumed-role/MyRole/MySession"
    role = ap._derive_role_arn_from_caller(caller)
    assert role == "arn:aws:iam::123456789012:role/MyRole"

    # Not an assumed-role ARN => None
    assert ap._derive_role_arn_from_caller("arn:aws:iam::123456789012:role/MyRole") is None
    assert ap._derive_role_arn_from_caller("") is None
    assert ap._derive_role_arn_from_caller(None) is None


def test_matches_requires_subject_token_and_getcalleridentity():
    a = ap.AwsPresignedAdapter()

    assert a.matches(_ctx("https://sts.amazonaws.com/?Action=GetCallerIdentity")) is True
    assert a.matches(_ctx("https://example/?action=getcalleridentity")) is True

    assert a.matches(_ctx("https://example/?Action=Other")) is False
    assert a.matches(_ctx("")) is False
    assert a.matches(_ctx(None)) is False


def test_verify_and_map_missing_subject_token_aborts_401(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")

    with pytest.raises(HTTPException) as excinfo:
        with pytest.MonkeyPatch().context() as _mp:
            # need a request context because adapter references flask.request

            app = Flask(__name__)
            with app.test_request_context("/authn/service/token", method="POST"):
                a.verify_and_map(_ctx(None), config={})

    assert _abort_code(excinfo.value) == 401


def test_verify_and_map_timeout_aborts_401_and_closes_session(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")

    sess = _SessionRaises(requests.Timeout("t"))
    monkeypatch.setattr(ap, "retrying_requests_session", lambda **kwargs: sess)

    app = Flask(__name__)
    with app.test_request_context("/authn/service/token", method="POST"):
        with pytest.raises(HTTPException) as excinfo:
            a.verify_and_map(_ctx("https://sts/?Action=GetCallerIdentity"), config={"bindings": []})

    assert _abort_code(excinfo.value) == 401
    assert sess.closed is True


def test_verify_and_map_request_exception_aborts_401_and_closes_session(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")

    sess = _SessionRaises(requests.RequestException("boom"))
    monkeypatch.setattr(ap, "retrying_requests_session", lambda **kwargs: sess)

    app = Flask(__name__)
    with app.test_request_context("/authn/service/token", method="POST"):
        with pytest.raises(HTTPException) as excinfo:
            a.verify_and_map(_ctx("https://sts/?Action=GetCallerIdentity"), config={"bindings": []})

    assert _abort_code(excinfo.value) == 401
    assert sess.closed is True


def test_verify_and_map_non_200_aborts_401(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")

    sess = _SessionOK(_Resp(status_code=403, text="SignatureDoesNotMatch"))
    monkeypatch.setattr(ap, "retrying_requests_session", lambda **kwargs: sess)

    app = Flask(__name__)
    with app.test_request_context("/authn/service/token", method="POST"):
        with pytest.raises(HTTPException) as excinfo:
            a.verify_and_map(_ctx("https://sts/?Action=GetCallerIdentity"), config={"bindings": []})

    assert _abort_code(excinfo.value) == 401


def test_verify_and_map_xml_missing_arn_aborts_401(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")

    xml = "<GetCallerIdentityResponse><GetCallerIdentityResult></GetCallerIdentityResult></GetCallerIdentityResponse>"
    sess = _SessionOK(_Resp(status_code=200, text=xml))
    monkeypatch.setattr(ap, "retrying_requests_session", lambda **kwargs: sess)

    app = Flask(__name__)
    with app.test_request_context("/authn/service/token", method="POST"):
        with pytest.raises(HTTPException) as excinfo:
            a.verify_and_map(_ctx("https://sts/?Action=GetCallerIdentity"), config={"bindings": []})

    assert _abort_code(excinfo.value) == 401


def test_verify_and_map_caller_not_assumed_role_aborts_401(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")

    xml = "<R><Arn>arn:aws:iam::123456789012:user/Bob</Arn></R>"
    sess = _SessionOK(_Resp(status_code=200, text=xml))
    monkeypatch.setattr(ap, "retrying_requests_session", lambda **kwargs: sess)

    app = Flask(__name__)
    with app.test_request_context("/authn/service/token", method="POST"):
        with pytest.raises(HTTPException) as excinfo:
            a.verify_and_map(_ctx("https://sts/?Action=GetCallerIdentity"), config={"bindings": []})

    assert _abort_code(excinfo.value) == 401


def test_verify_and_map_role_not_allowed_aborts_403(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")

    xml = "<R><Arn>arn:aws:sts::123456789012:assumed-role/MyRole/MySession</Arn></R>"
    sess = _SessionOK(_Resp(status_code=200, text=xml))
    monkeypatch.setattr(ap, "retrying_requests_session", lambda **kwargs: sess)

    cfg = {"bindings": []}  # no matching role_arn


    app = Flask(__name__)
    with app.test_request_context("/authn/service/token", method="POST"):
        with pytest.raises(HTTPException) as excinfo:
            a.verify_and_map(_ctx("https://sts/?Action=GetCallerIdentity"), config=cfg)

    assert _abort_code(excinfo.value) == 403


def test_verify_and_map_success_maps_subject_authz_policy_and_proof(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")
    monkeypatch.setattr(ap.time, "time", lambda: 1700000000.0)

    xml = "<R><Arn>arn:aws:sts::123456789012:assumed-role/MyRole/MySession</Arn></R>"
    sess = _SessionOK(_Resp(status_code=200, text=xml))
    monkeypatch.setattr(ap, "retrying_requests_session", lambda **kwargs: sess)

    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    cfg = {
        "bindings": [
            {
                "role_arn": role_arn,
                "scopes": ["openid", "email"],
                "resources": ["rest-api"],
                "groups": ["g1"],
                "email": "owner@example.org",
                "name": "svc-myrole",
                "default_scopes": ["openid"],
                "max_ttl_seconds": 900,
            }
        ]
    }

    app = Flask(__name__)
    with app.test_request_context("/authn/service/token", method="POST"):
        res = a.verify_and_map(_ctx("https://sts/?Action=GetCallerIdentity"), config=cfg)

    assert res.subject.provider == "aws"
    assert res.subject.subject_id == role_arn

    assert res.authz.scopes == ["openid", "email"]
    assert res.authz.resources == ["rest-api"]
    assert res.authz.groups == ["g1"]
    assert res.authz.email == "owner@example.org"
    assert res.authz.name == "svc-myrole"
    assert res.authz.realm == "credenza"  # default in ServiceAuthorization

    assert res.proof["type"] == "aws_presigned_gci"
    assert res.proof["principal"] == role_arn
    assert res.proof["issued_at"] == 1700000000
    assert res.proof["caller_arn"].startswith("arn:aws:sts::123456789012:assumed-role/")

    assert res.policy.default_scopes == ["openid"]
    assert res.policy.max_ttl_seconds == 900


def test_verify_and_map_policy_defaults_when_missing(monkeypatch):
    a = ap.AwsPresignedAdapter()

    monkeypatch.setattr(ap, "get_correlation_id", lambda req: "rid")
    monkeypatch.setattr(ap, "client_ip", lambda req: "1.2.3.4")
    monkeypatch.setattr(ap.time, "time", lambda: 1700000000.0)

    xml = "<R><Arn>arn:aws:sts::123456789012:assumed-role/MyRole/MySession</Arn></R>"
    sess = _SessionOK(_Resp(status_code=200, text=xml))
    monkeypatch.setattr(ap, "retrying_requests_session", lambda **kwargs: sess)

    role_arn = "arn:aws:iam::123456789012:role/MyRole"
    cfg = {"bindings": [{"role_arn": role_arn, "scopes": ["s1"], "resources": ["a1"]}]}

    app = Flask(__name__)
    with app.test_request_context("/authn/service/token", method="POST"):
        res = a.verify_and_map(_ctx("https://sts/?Action=GetCallerIdentity"), config=cfg)

    assert res.policy.default_scopes == []
    assert res.policy.max_ttl_seconds == DEFAULT_MAX_TTL
