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
from credenza.api.common.claim_mapper import build_realm_claim_maps
from credenza.telemetry import audit_identity, audit_identity_snapshot
from credenza.telemetry.audit.identity import PII_CLAIMS

ISS = "https://idp.example.org"
USERINFO = {
    "iss": ISS,
    "sub": "abc123",
    "preferred_username": "alice",
    "name": "Alice Example",
    "email": "alice@example.org",
    "email_verified": True,
}


class _IdentitiesProvider:
    def __init__(self, identities=None, exc=None):
        self._identities = identities or {}
        self._exc = exc

    def build_identities(self, userinfo):
        if self._exc:
            raise self._exc
        return self._identities


def test_audit_identity_composes_iss_and_sub(app):
    with app.app_context():
        fields = audit_identity(USERINFO, "test")
    assert fields == {"iss": ISS, "sub": "abc123", "identity": f"{ISS}/abc123"}


def test_audit_identity_never_includes_pii(app):
    with app.app_context():
        fields = audit_identity(USERINFO, "test")
    assert not set(PII_CLAIMS) & set(fields)
    assert "identities" not in fields


def test_audit_identity_service_subject_without_issuer(app):
    with app.app_context():
        fields = audit_identity({"sub": "svc-client", "name": "Service"}, "test")
    assert fields == {"iss": None, "sub": "svc-client", "identity": "svc-client"}


def test_audit_identity_empty_issuer_is_null(app):
    with app.app_context():
        fields = audit_identity({"iss": "", "sub": "abc123"}, "test")
    assert fields == {"iss": None, "sub": "abc123", "identity": "abc123"}


def test_audit_identity_tolerates_missing_userinfo_and_app_context():
    assert audit_identity(None) == {"iss": None, "sub": None, "identity": None}
    assert audit_identity({"iss": ISS, "sub": "abc123"})["identity"] == f"{ISS}/abc123"


def test_snapshot_includes_pii_and_linked_identities(app, monkeypatch):
    linked = {f"{ISS}/abc123": {}, f"{ISS}/def456": {}}
    monkeypatch.setitem(app.config["SESSION_AUGMENTATION_PROVIDERS"], "test", _IdentitiesProvider(linked))
    with app.app_context():
        fields = audit_identity_snapshot(USERINFO, "test")
    assert fields == {
        "iss": ISS,
        "sub": "abc123",
        "identity": f"{ISS}/abc123",
        "preferred_username": "alice",
        "full_name": "Alice Example",
        "email": "alice@example.org",
        "email_verified": True,
        "identities": [f"{ISS}/abc123", f"{ISS}/def456"],
    }


def test_snapshot_resolves_claims_through_realm_claim_map(app):
    app.config["IDP_CLAIM_MAPS"] = build_realm_claim_maps(
        {"test": {"claim_map_overrides": {"email": ["mail"]}}})
    with app.app_context():
        fields = audit_identity_snapshot({"iss": ISS, "sub": "abc123", "mail": "a@example.org"}, "test")
    assert fields["email"] == "a@example.org"


def test_snapshot_reduces_to_identity_when_pii_disabled(app):
    app.config["AUDIT_INCLUDE_PII"] = False
    with app.app_context():
        assert audit_identity_snapshot(USERINFO, "test") == audit_identity(USERINFO, "test")


def test_snapshot_survives_failing_identities_provider(app, monkeypatch):
    monkeypatch.setitem(app.config["SESSION_AUGMENTATION_PROVIDERS"], "test",
                        _IdentitiesProvider(exc=RuntimeError("boom")))
    with app.app_context():
        fields = audit_identity_snapshot(USERINFO, "test")
    assert fields["identities"] == []
    assert fields["email"] == "alice@example.org"


def test_snapshot_unknown_realm_has_no_linked_identities(app):
    with app.app_context():
        assert audit_identity_snapshot(USERINFO, "no-such-realm")["identities"] == []
