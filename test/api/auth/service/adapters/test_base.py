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
from credenza.api.auth.service.adapters import base as b


def test_not_empty_accepts_and_rejects():
    assert b._not_empty("x", "field") == "x"
    with pytest.raises(ValueError, match="field is required"):
        b._not_empty("", "field")
    with pytest.raises(ValueError, match="field is required"):
        b._not_empty(None, "field")


def test_no_ws_rejects_whitespace():
    b._no_ws("abc", "field")
    with pytest.raises(ValueError, match="field must not contain whitespace"):
        b._no_ws("a b", "field")
    with pytest.raises(ValueError, match="field must not contain whitespace"):
        b._no_ws("a\tb", "field")
    with pytest.raises(ValueError, match="field must not contain whitespace"):
        b._no_ws("a\nb", "field")


def test_bounded_rejects_over_limit():
    b._bounded("a" * b._MAX_ID_LEN, "field", b._MAX_ID_LEN)
    with pytest.raises(ValueError, match=f"field exceeds {b._MAX_ID_LEN} characters"):
        b._bounded("a" * (b._MAX_ID_LEN + 1), "field", b._MAX_ID_LEN)


def test_check_tokens_validates_entries_and_size():
    out = b._check_tokens("scopes", ["a", "b", "c"])
    assert out == ["a", "b", "c"]

    with pytest.raises(ValueError, match="scopes must not be empty"):
        b._check_tokens("scopes", [])

    with pytest.raises(ValueError, match="scopes has too many entries"):
        b._check_tokens("scopes", ["x"] * (b._MAX_LIST_LEN + 1))

    with pytest.raises(ValueError, match="scopes entry is required"):
        b._check_tokens("scopes", [""])

    with pytest.raises(ValueError, match="scopes entry must not contain whitespace"):
        b._check_tokens("scopes", ["has space"])

    # bounded by _MAX_TOKEN_LEN
    with pytest.raises(ValueError, match=f"scopes entry exceeds {b._MAX_TOKEN_LEN} characters"):
        b._check_tokens("scopes", ["x" * (b._MAX_TOKEN_LEN + 1)])


def test_find_unique_adapter_binding_none_and_unique_and_multiple():
    cfg = {"bindings": [{"client_id": "a", "x": 1}, {"client_id": "b", "x": 2}]}
    assert b.find_unique_adapter_binding("client_id", "nope", cfg) is None

    m = b.find_unique_adapter_binding("client_id", "a", cfg)
    assert m == {"client_id": "a", "x": 1}

    cfg2 = {"bindings": [{"k": "v"}, {"k": "v"}]}
    with pytest.raises(ValueError, match="Multiple bindings matched k=v"):
        b.find_unique_adapter_binding("k", "v", cfg2)


def test_proof_context_get_and_getlist_and_header_case_insensitive():
    ctx = b.ProofContext(
        form={
            "single": "v1",
            "multi": ["a", "b"],
            "empty_list": [],
        },
        headers={
            "X-Thing": "T1",
            "x-other": "T2",
        }
    )

    assert ctx.get("single") == "v1"
    assert ctx.get("multi") == "a"
    assert ctx.get("missing") is None
    assert ctx.get("missing", "d") == "d"
    assert ctx.get("empty_list", "d") == "d"

    assert ctx.getlist("single") == ["v1"]
    assert ctx.getlist("multi") == ["a", "b"]
    assert ctx.getlist("missing") == []

    assert ctx.header("x-thing") == "T1"
    assert ctx.header("X-THING") == "T1"
    assert ctx.header("X-Other") == "T2"
    assert ctx.header("missing") is None
    assert ctx.header("missing", "d") == "d"


def test_service_subject_validation_and_to_sub():
    s = b.ServiceSubject(provider="aws", subject_id="arn:aws:iam::123:role/foo")
    assert s.provider == "aws"
    assert s.to_sub().startswith(b.DEFAULT_SERVICE_AUTH_URN + ":")

    with pytest.raises(ValueError, match="ServiceSubject.provider is required"):
        b.ServiceSubject(provider="", subject_id="x")

    with pytest.raises(ValueError, match="ServiceSubject.subject_id is required"):
        b.ServiceSubject(provider="aws", subject_id="")

    with pytest.raises(ValueError, match="ServiceSubject.provider must not contain whitespace"):
        b.ServiceSubject(provider="a ws", subject_id="x")

    with pytest.raises(ValueError, match="ServiceSubject.subject_id must not contain whitespace"):
        b.ServiceSubject(provider="aws", subject_id="x y")

    with pytest.raises(ValueError, match="ServiceSubject.provider exceeds 32 characters"):
        b.ServiceSubject(provider="x" * 33, subject_id="id")

    with pytest.raises(ValueError, match=f"ServiceSubject.subject_id exceeds {b._MAX_ID_LEN} characters"):
        b.ServiceSubject(provider="aws", subject_id="x" * (b._MAX_ID_LEN + 1))


def test_service_authorization_valid_and_optional_fields():
    a = b.ServiceAuthorization(
        scopes=["openid", "email"],
        audiences=["aud1"],
        groups=["g1", "g2"],
        name="svc-name",
        email="svc@example.org",
        realm="test",
    )
    assert a.scopes == ["openid", "email"]
    assert a.audiences == ["aud1"]
    assert a.groups == ["g1", "g2"]
    assert a.name == "svc-name"
    assert a.email == "svc@example.org"
    assert a.realm == "test"


def test_service_authorization_requires_scopes_and_audiences():
    with pytest.raises(ValueError, match="scopes must not be empty"):
        b.ServiceAuthorization(scopes=[], audiences=["aud1"])

    with pytest.raises(ValueError, match="audiences must not be empty"):
        b.ServiceAuthorization(scopes=["s1"], audiences=[])


def test_service_authorization_groups_optional_but_validated_when_present():
    a = b.ServiceAuthorization(scopes=["s1"], audiences=["a1"], groups=[])
    assert a.groups == []

    with pytest.raises(ValueError, match="groups entry must not contain whitespace"):
        b.ServiceAuthorization(scopes=["s1"], audiences=["a1"], groups=["bad group"])


def test_service_authorization_email_and_realm_validation():
    with pytest.raises(ValueError, match="email must not contain whitespace"):
        b.ServiceAuthorization(scopes=["s1"], audiences=["a1"], email="a b@example.org")

    with pytest.raises(ValueError, match=f"email exceeds {b._MAX_EMAIL_LEN} characters"):
        b.ServiceAuthorization(scopes=["s1"], audiences=["a1"], email=("a" * (b._MAX_EMAIL_LEN + 1)))

    with pytest.raises(ValueError, match="realm must not contain whitespace"):
        b.ServiceAuthorization(scopes=["s1"], audiences=["a1"], realm="bad realm")

    with pytest.raises(ValueError, match=f"realm exceeds {b._MAX_REALM_LEN} characters"):
        b.ServiceAuthorization(scopes=["s1"], audiences=["a1"], realm=("r" * (b._MAX_REALM_LEN + 1)))

    with pytest.raises(ValueError, match="realm is required"):
        b.ServiceAuthorization(scopes=["s1"], audiences=["a1"], realm="")  # empty


def test_service_issue_result_requires_proof_type_and_valid_realm():
    subj = b.ServiceSubject(provider="aws", subject_id="id")
    authz = b.ServiceAuthorization(scopes=["s1"], audiences=["a1"])

    # proof must be dict with non-empty 'type'
    with pytest.raises(ValueError, match="proof must include a non-empty 'type'"):
        b.ServiceIssueResult(subject=subj, authz=authz, proof={})

    with pytest.raises(ValueError, match="proof must include a non-empty 'type'"):
        b.ServiceIssueResult(subject=subj, authz=authz, proof={"type": ""})

    # realm validation
    with pytest.raises(ValueError, match="realm must not contain whitespace"):
        b.ServiceIssueResult(subject=subj, authz=authz, proof={"type": "x"}, realm="bad realm")

    with pytest.raises(ValueError, match=f"realm exceeds {b._MAX_REALM_LEN} characters"):
        b.ServiceIssueResult(subject=subj, authz=authz, proof={"type": "x"}, realm=("r" * (b._MAX_REALM_LEN + 1)))

    ok = b.ServiceIssueResult(subject=subj, authz=authz, proof={"type": "x"}, realm="test")
    assert ok.realm == "test"
    assert ok.proof["type"] == "x"


def test_service_policy_defaults():
    p = b.ServicePolicy()
    assert p.default_scopes == []
    assert p.max_ttl_seconds == b.DEFAULT_MAX_TTL


def test_service_auth_adapter_is_abstract():
    # ABC cannot be instantiated directly
    with pytest.raises(TypeError):
        b.ServiceAuthAdapter()
