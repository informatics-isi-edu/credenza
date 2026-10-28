#
# Copyright 2026 University of Southern California
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
from types import SimpleNamespace
from flask import g
from requests import HTTPError
from requests.models import Response
from credenza.api.session.augmentation.deriva_provider import (
    DerivaErmrestSessionAugmentationProvider,
    RasDerivaErmrestSessionAugmentationProvider,
)
from credenza.api.session.augmentation.ras_provider import RasSessionAugmentationProvider

ISS = "https://sts.nih.gov"
SUB = "abc123"
CLIENT_ID = f"{ISS}/{SUB}"

ROLE_QUERY = {
    "name": "assigned_roles",
    "url": "https://host/ermrest/catalog/1/attribute/s:user_role/user={client_id}/s:role/name,description",
    "claim": "roles",
    "id": "tag:example.org,2026:role/{name}",
    "display_name": "{description}",
}
DATASET_QUERY = {
    "name": "dar_datasets",
    "url": "https://host/ermrest/catalog/1/attribute/s:DAR/RCB={client_id}/status=approved/isa:dataset/RID,title",
    "id": "tag:example.org,2026:dataset/{RID}",
    "display_name": "{title}",
}


def ok(rows):
    return SimpleNamespace(status_code=200, json=lambda: rows, raise_for_status=lambda: None)


def http_error(status):
    def raise_for_status():
        resp = Response()
        resp.status_code = status
        raise HTTPError(response=resp)
    return SimpleNamespace(status_code=status, json=lambda: None, raise_for_status=raise_for_status)


@pytest.fixture
def provider(app, monkeypatch):
    """A provider for the 'ermrest' realm, with default query config."""
    configure(app, monkeypatch, [ROLE_QUERY, DATASET_QUERY])
    return DerivaErmrestSessionAugmentationProvider("ermrest")


def configure(app, monkeypatch, queries, **extra):
    params = {"defer_augmentation": True, **extra}
    if queries is not None:
        params["ermrest_role_queries"] = queries
    monkeypatch.setitem(app.config, "OIDC_IDP_PROFILES", {"ermrest": {"session_augmentation_params": params}})


@pytest.fixture
def responses(monkeypatch):
    """Route requests.get by URL substring; record each call."""
    routes = {}
    calls = []

    def fake_get(url, headers, timeout, verify):
        calls.append({"url": url, "headers": headers, "timeout": timeout, "verify": verify})
        for key, resp in routes.items():
            if key in url:
                if isinstance(resp, Exception):
                    raise resp
                return resp
        return ok([])

    monkeypatch.setattr(requests, "get", fake_get)
    return SimpleNamespace(routes=routes, calls=calls)


def enrich(app, provider, userinfo, session_key="user-key"):
    with app.test_request_context():
        if session_key is not None:
            g.session_key = session_key
        return provider.enrich_userinfo(userinfo, {})


def userinfo():
    return {"iss": ISS, "sub": SUB}


def test_maps_rows_into_roles(app, provider, responses):
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    responses.routes["s:DAR"] = ok([{"RID": "1-ABCD", "title": "Mouse study"}])
    ui = userinfo()

    assert enrich(app, provider, ui) is True
    assert ui["roles"] == [
        {"id": "tag:example.org,2026:role/curator", "display_name": "Curator"},
        {"id": "tag:example.org,2026:dataset/1-ABCD", "display_name": "Mouse study"},
    ]


def test_uses_user_session_key_and_encoded_client_id(app, provider, responses):
    enrich(app, provider, userinfo(), session_key="the-user-key")

    assert len(responses.calls) == 2
    call = responses.calls[0]
    assert call["headers"]["Authorization"] == "Bearer the-user-key"
    assert call["headers"]["Accept"] == "application/json"
    assert "user=https%3A%2F%2Fsts.nih.gov%2Fabc123/s:role" in call["url"]
    assert call["timeout"] == 5
    assert call["verify"] is True


def test_encoding_keeps_hostile_sub_a_single_literal(app, provider, responses):
    ui = {"iss": ISS, "sub": "x/s:role/name=admin;a"}
    enrich(app, provider, ui)
    assert "user=https%3A%2F%2Fsts.nih.gov%2Fx%2Fs%3Arole%2Fname%3Dadmin%3Ba/s:role" in responses.calls[0]["url"]


def test_client_id_without_iss_is_bare_sub(app, provider, responses):
    enrich(app, provider, {"sub": SUB})
    assert f"user={SUB}/s:role" in responses.calls[0]["url"]


def test_timeout_and_cert_params(app, provider, responses, monkeypatch):
    configure(app, monkeypatch, [ROLE_QUERY], ermrest_timeout=12, ermrest_bypass_cert_verify=True)
    enrich(app, provider, userinfo())
    assert responses.calls[0]["timeout"] == 12
    assert responses.calls[0]["verify"] is False


def test_claim_groups_and_display_name_defaults_to_id(app, provider, responses, monkeypatch):
    query = {"name": "g", "url": "https://host/q/{client_id}", "claim": "groups", "id": "urn:g:{RID}"}
    configure(app, monkeypatch, [query])
    responses.routes["/q/"] = ok([{"RID": "1"}])
    ui = userinfo()
    enrich(app, provider, ui)
    assert ui["groups"] == [{"id": "urn:g:1", "display_name": "urn:g:1"}]
    assert "roles" not in ui


def test_repeat_enrich_replaces_rather_than_duplicates(app, provider, responses):
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    ui = userinfo()
    enrich(app, provider, ui)
    enrich(app, provider, ui)
    assert [e["id"] for e in ui["roles"]] == ["tag:example.org,2026:role/curator"]


def test_revoked_role_is_removed_on_next_enrich(app, provider, responses):
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"},
                                           {"name": "admin", "description": "Admin"}])
    ui = userinfo()
    enrich(app, provider, ui)
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    enrich(app, provider, ui)
    assert [e["id"] for e in ui["roles"]] == ["tag:example.org,2026:role/curator"]


def test_idp_supplied_entries_are_preserved(app, provider, responses):
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    ui = {**userinfo(), "roles": ["idp-role"], "groups": [{"id": "idp-group", "display_name": "G"}]}
    enrich(app, provider, ui)
    responses.routes["s:user_role"] = ok([])
    enrich(app, provider, ui)
    assert ui["roles"] == ["idp-role"]
    assert ui["groups"] == [{"id": "idp-group", "display_name": "G"}]


def test_entry_matching_idp_entry_is_not_duplicated_or_later_removed(app, provider, responses):
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    ui = {**userinfo(), "roles": ["tag:example.org,2026:role/curator"]}
    enrich(app, provider, ui)
    assert ui["roles"] == ["tag:example.org,2026:role/curator"]
    responses.routes["s:user_role"] = ok([])
    enrich(app, provider, ui)
    assert ui["roles"] == ["tag:example.org,2026:role/curator"]


def test_failed_query_fails_closed_but_others_still_apply(app, provider, responses):
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    responses.routes["s:DAR"] = ok([{"RID": "1-ABCD", "title": "Mouse study"}])
    ui = userinfo()
    enrich(app, provider, ui)

    responses.routes["s:user_role"] = http_error(500)
    assert enrich(app, provider, ui) is True
    assert [e["id"] for e in ui["roles"]] == ["tag:example.org,2026:dataset/1-ABCD"]


@pytest.mark.parametrize("failure", [
    http_error(401),
    RuntimeError("network down"),
    ok({"not": "a list"}),
])
def test_all_queries_failing_returns_false_and_drops_entries(app, provider, responses, failure):
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    ui = userinfo()
    enrich(app, provider, ui)

    responses.routes["s:user_role"] = failure
    responses.routes["s:DAR"] = failure
    assert enrich(app, provider, ui) is False
    assert ui["roles"] == []
    assert DerivaErmrestSessionAugmentationProvider.AUGMENTED_KEY not in ui


def test_no_session_key_drops_entries_and_skips_queries(app, provider, responses, monkeypatch):
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    ui = userinfo()
    enrich(app, provider, ui)
    responses.calls.clear()

    monkeypatch.setattr("credenza.api.session.augmentation.deriva_provider.extract_session_key",
                        lambda: (None, False))
    assert enrich(app, provider, ui, session_key=None) is False
    assert responses.calls == []
    assert ui["roles"] == []


def test_falls_back_to_request_session_key(app, provider, responses, monkeypatch):
    monkeypatch.setattr("credenza.api.session.augmentation.deriva_provider.extract_session_key",
                        lambda: ("cookie-key", False))
    enrich(app, provider, userinfo(), session_key=None)
    assert responses.calls[0]["headers"]["Authorization"] == "Bearer cookie-key"


def test_missing_query_config(app, provider, responses, monkeypatch):
    configure(app, monkeypatch, None)
    ui = userinfo()
    assert enrich(app, provider, ui) is False
    assert responses.calls == []
    assert "roles" not in ui


def test_missing_sub(app, provider, responses):
    assert enrich(app, provider, {"iss": ISS}) is False
    assert responses.calls == []


@pytest.mark.parametrize("query", [
    {"name": "no-url", "id": "x:{RID}"},
    {"name": "no-id", "url": "https://host/q/{client_id}"},
    {"name": "bad-claim", "url": "https://host/q/{client_id}", "id": "x:{RID}", "claim": "scopes"},
    {"name": "linked", "url": "https://host/q/{identities}", "id": "x:{RID}"},
    {"name": "email", "url": "https://host/q/{email}", "id": "x:{RID}"},
])
def test_invalid_query_is_skipped(app, provider, responses, monkeypatch, query):
    configure(app, monkeypatch, [query])
    ui = {**userinfo(), "email": "u@example.org"}
    assert enrich(app, provider, ui) is False
    assert responses.calls == []
    assert "roles" not in ui


def test_rows_missing_or_null_columns_are_skipped(app, provider, responses):
    responses.routes["s:user_role"] = ok([
        {"name": "curator", "description": "Curator"},
        {"description": "no name"},
        {"name": None, "description": "null name"},
        {"name": "submitter", "description": None},
    ])
    ui = userinfo()
    enrich(app, provider, ui)
    assert [e["id"] for e in ui["roles"]] == ["tag:example.org,2026:role/curator"]


def test_row_values_are_not_encoded_in_ids(app, provider, responses):
    responses.routes["s:user_role"] = ok([{"name": "data/curator", "description": "D C"}])
    ui = userinfo()
    enrich(app, provider, ui)
    assert ui["roles"][0] == {"id": "tag:example.org,2026:role/data/curator", "display_name": "D C"}


def test_uses_own_realm_profile_not_default(app, responses, monkeypatch):
    monkeypatch.setitem(app.config, "OIDC_IDP_PROFILES", {
        "test": {"session_augmentation_params": {"ermrest_role_queries": [
            {"name": "wrong", "url": "https://wrong/{client_id}", "id": "x:{RID}"}]}},
        "ermrest": {"session_augmentation_params": {"ermrest_role_queries": [ROLE_QUERY]}},
    })
    enrich(app, DerivaErmrestSessionAugmentationProvider("ermrest"), userinfo())
    assert [c["url"].split("/")[2] for c in responses.calls] == ["host"]


def test_client_id_honours_realm_claim_map(app, provider, responses, monkeypatch):
    monkeypatch.setitem(app.config, "IDP_CLAIM_MAPS", {"ermrest": {"sub": ["ras_sub"]}})
    enrich(app, provider, {"iss": ISS, "ras_sub": "mapped"})
    assert "user=https%3A%2F%2Fsts.nih.gov%2Fmapped/s:role" in responses.calls[0]["url"]


def test_ras_compound_provider_composes_both(app, responses, monkeypatch):
    provider = RasDerivaErmrestSessionAugmentationProvider("ermrest")
    configure(app, monkeypatch, [ROLE_QUERY])
    responses.routes["s:user_role"] = ok([{"name": "curator", "description": "Curator"}])
    ui = {
        **userinfo(),
        "federated_identities_ial2": {
            "sources": {"login.gov": {"identity_username": "u@login.gov", "ial": 2}},
            "identities": {"login.gov": {"mail": "u@example.org"}},
            "authenticated_identity": "u@login.gov",
        },
    }

    assert enrich(app, provider, ui) is True
    assert [e["id"] for e in ui["roles"]] == ["tag:example.org,2026:role/curator"]
    assert provider.build_identities(ui)["u@login.gov"]["authenticated"] is True
    # Linked identities never reach the query.
    assert "login.gov" not in responses.calls[0]["url"]


def test_ras_compound_provider_mro():
    mro = RasDerivaErmrestSessionAugmentationProvider.__mro__
    assert mro.index(RasSessionAugmentationProvider) < mro.index(DerivaErmrestSessionAugmentationProvider)
