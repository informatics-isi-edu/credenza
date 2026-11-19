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
from flask import Flask
from credenza.telemetry.audit import attributes as aa
from credenza.api.session.augmentation.base_provider import EnrichmentResult

TAG = "tag:example.org,2026:"
SPEC = [
    {"field": "permissions", "claim": "roles",
     "match": r"^tag:example\.org,2026:(grant/.+)$", "emit": r"\1"},
    {"field": "user_roles", "claim": "roles",
     "match": r"^tag:example\.org,2026:(role/.+)$", "emit": r"\1"},
]
USERINFO = {
    "iss": "https://idp.example.org",
    "sub": "abc",
    "roles": [
        {"id": TAG + "role/Registered", "display_name": "Registered"},
        {"id": TAG + "grant/1-ABC2", "display_name": "Grant 1-ABC2"},
        TAG + "grant/1-DEF4",
        {"id": TAG + "grant/1-ABC2", "display_name": "duplicate"},
        {"display_name": "no id"},
        42,
    ],
}


@pytest.fixture
def app():
    a = Flask(__name__)
    a.config["IDP_CLAIM_MAPS"] = {}
    a.config["AUDIT_INCLUDE_PII"] = True
    a.config["AUDIT_ATTRIBUTE_SELECTORS"] = {"ras": aa.parse_audit_attributes(SPEC, "ras")}
    return a


@pytest.fixture
def events(monkeypatch):
    captured = []
    monkeypatch.setattr(aa, "audit_event", lambda e, **kw: captured.append((e, kw)))
    return captured


# --- validation -------------------------------------------------------------------------------

@pytest.mark.parametrize("entry, message", [
    ({"field": "1bad", "claim": "roles"}, "field"),
    ({"field": "f"}, "claim"),
    ({"field": "f", "claim": "roles", "select": "name"}, "select"),
    ({"field": "f", "claim": "roles", "match": "("}, "regular expression"),
    ({"field": "f", "claim": "roles", "emit": r"\1"}, "requires 'match'"),
    ({"field": "f", "claim": "roles", "match": "(a)", "emit": r"\2"}, "group 2"),
    ({"field": "f", "claim": "roles", "match": "(a)", "emit": r"\g<x>"}, "unknown group"),
    ({"field": "f", "claim": "roles", "pii": "yes"}, "pii"),
    ({"field": "f", "claim": "roles", "max_values": 0}, "max_values"),
    ({"field": "f", "claim": "roles", "colour": "red"}, "unknown keys"),
])
def test_parse_rejects_malformed_entries(entry, message):
    with pytest.raises(ValueError, match=message):
        aa.parse_audit_attributes([entry], "ras")


def test_parse_rejects_duplicate_fields_and_non_list():
    with pytest.raises(ValueError, match="repeats"):
        aa.parse_audit_attributes([{"field": "f", "claim": "a"}, {"field": "f", "claim": "b"}], "ras")
    with pytest.raises(ValueError, match="must be a list"):
        aa.parse_audit_attributes({"field": "f"}, "ras")


def test_build_realm_selectors_skips_realms_without_spec_and_fails_on_bad_one():
    selectors = aa.build_realm_attribute_selectors({"ras": {"audit_attributes": SPEC}, "globus": {}})
    assert set(selectors) == {"ras"}
    with pytest.raises(ValueError):
        aa.build_realm_attribute_selectors({"ras": {"audit_attributes": [{"field": "f"}]}})


# --- selection --------------------------------------------------------------------------------

def test_select_applies_match_and_emit_dedupes_and_sorts(app):
    with app.app_context():
        selected, truncated = aa.select_session_attributes(USERINFO, "ras")
    assert selected == {
        "permissions": ["grant/1-ABC2", "grant/1-DEF4"],
        "user_roles": ["role/Registered"],
    }
    assert truncated == []


def test_select_display_name_and_value_length_cap(app):
    app.config["AUDIT_ATTRIBUTE_SELECTORS"] = {"ras": aa.parse_audit_attributes(
        [{"field": "names", "claim": "roles", "select": "display_name"}], "ras")}
    userinfo = {"roles": [{"id": "x", "display_name": "n" * 1000}]}
    with app.app_context():
        selected, _ = aa.select_session_attributes(userinfo, "ras")
    assert selected["names"] == ["n" * aa.MAX_VALUE_LEN]


def test_select_reports_truncation_at_max_values(app):
    app.config["AUDIT_ATTRIBUTE_SELECTORS"] = {"ras": aa.parse_audit_attributes(
        [{"field": "r", "claim": "roles", "max_values": 2}], "ras")}
    with app.app_context():
        selected, truncated = aa.select_session_attributes({"roles": ["c", "a", "b"]}, "ras")
    assert selected["r"] == ["a", "b"]
    assert truncated == ["r"]


def test_select_omits_pii_fields_when_pii_disabled(app):
    app.config["AUDIT_ATTRIBUTE_SELECTORS"] = {"ras": aa.parse_audit_attributes(
        [{"field": "country", "claim": "country", "pii": True},
         {"field": "r", "claim": "roles"}], "ras")}
    app.config["AUDIT_INCLUDE_PII"] = False
    with app.app_context():
        selected, _ = aa.select_session_attributes({"country": "US", "roles": ["a"]}, "ras")
    assert selected == {"r": ["a"]}


def test_select_resolves_claim_through_realm_claim_map(app):
    app.config["IDP_CLAIM_MAPS"] = {"ras": {"org_unit": ["department"]}}
    app.config["AUDIT_ATTRIBUTE_SELECTORS"] = {"ras": aa.parse_audit_attributes(
        [{"field": "unit", "claim": "org_unit"}], "ras")}
    with app.app_context():
        selected, _ = aa.select_session_attributes({"department": "Research Computing"}, "ras")
    assert selected == {"unit": ["Research Computing"]}


# --- event ------------------------------------------------------------------------------------

def test_no_event_for_realm_without_selectors(app, events):
    with app.app_context():
        aa.audit_session_attributes("s1", USERINFO, "globus", trigger="login")
    assert events == []


def test_login_event_records_everything_as_added(app, events):
    with app.test_request_context("/"):
        aa.audit_session_attributes("s1", USERINFO, "ras", trigger="login")
    (event, kw), = events
    assert event == "session_attributes_updated"
    assert kw["session_id"] == "s1"
    assert kw["identity"] == "https://idp.example.org/abc"
    assert kw["trigger"] == "login"
    assert kw["complete"] is True
    assert kw["added"] == kw["attributes"]
    assert kw["removed"] == {}
    assert "failed_sources" not in kw


def test_login_event_written_even_when_nothing_selected(app, events):
    with app.test_request_context("/"):
        aa.audit_session_attributes("s1", {"sub": "abc"}, "ras", trigger="login")
    (_, kw), = events
    assert kw["attributes"] == {"permissions": [], "user_roles": []}


def test_failed_source_marks_event_incomplete(app, events):
    with app.test_request_context("/"):
        aa.audit_session_attributes("s1", USERINFO, "ras", trigger="login",
                                    enrichment=EnrichmentResult(failed_sources=("grant_query",)))
    (_, kw), = events
    assert kw["complete"] is False
    assert kw["failed_sources"] == ["grant_query"]


def test_refresh_without_change_writes_nothing(app, events):
    with app.test_request_context("/"):
        before, _ = aa.select_session_attributes(USERINFO, "ras")
        aa.audit_session_attributes("s1", USERINFO, "ras", trigger="refresh", before=before)
    assert events == []


def test_refresh_with_change_records_added_and_removed(app, events):
    after = {"sub": "abc", "roles": [TAG + "grant/1-GHI6", TAG + "role/Registered"]}
    with app.test_request_context("/"):
        before, _ = aa.select_session_attributes(USERINFO, "ras")
        aa.audit_session_attributes("s1", after, "ras", trigger="refresh", before=before)
    (_, kw), = events
    assert kw["trigger"] == "refresh"
    assert kw["attributes"]["permissions"] == ["grant/1-GHI6"]
    assert kw["added"] == {"permissions": ["grant/1-GHI6"]}
    assert kw["removed"] == {"permissions": ["grant/1-ABC2", "grant/1-DEF4"]}


def test_refresh_with_failure_but_no_change_is_still_recorded(app, events):
    with app.test_request_context("/"):
        before, _ = aa.select_session_attributes(USERINFO, "ras")
        aa.audit_session_attributes("s1", USERINFO, "ras", trigger="refresh", before=before,
                                    enrichment=EnrichmentResult(failed_sources=("grant_query",)))
    (_, kw), = events
    assert kw["complete"] is False
    assert kw["added"] == {} and kw["removed"] == {}
