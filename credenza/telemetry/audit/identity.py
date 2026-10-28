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
import logging
from flask import current_app, has_app_context
from ...api.common.claim_mapper import DEFAULT_CLAIM_MAP, get_claim_map_for_realm, resolve_claim

logger = logging.getLogger(__name__)

# Identifying personal information recorded in an identity snapshot, as canonical claim names
PII_CLAIMS = ("preferred_username", "full_name", "email", "email_verified")


def _claim_map(realm):
    realm_maps = current_app.config.get("IDP_CLAIM_MAPS") if has_app_context() else None
    return get_claim_map_for_realm(realm or "default", realm_maps or {}) or DEFAULT_CLAIM_MAP


def _include_pii():
    if not has_app_context():
        return True
    return bool(current_app.config.get("AUDIT_INCLUDE_PII", True))


def _linked_identities(userinfo, realm):
    if not has_app_context():
        return []
    provider = (current_app.config.get("SESSION_AUGMENTATION_PROVIDERS") or {}).get(realm)
    if provider is None:
        return []
    try:
        return sorted(provider.build_identities(userinfo) or {})
    except Exception:
        logger.exception(f"Failed to build linked identities for audit on realm {realm}")
        return []


def audit_identity(userinfo, realm=None):
    """Return the identifier fields that every audit record about a subject carries.

    `sub` is only unique within its issuer, so `iss` is always recorded with it. `identity`
    is "<iss>/<sub>", formed exactly as GET /session forms the client id, which is also the
    id ERMrest records for the client (ERMrest_client.ID, RCB/RMB). Service sessions have no
    issuer, so their identity is the bare sub. No personal information is included.
    """
    userinfo = userinfo or {}
    claim_map = _claim_map(realm)
    iss = resolve_claim(userinfo, claim_map, "iss", userinfo.get("iss")) or None
    sub = resolve_claim(userinfo, claim_map, "sub", userinfo.get("sub")) or None
    return {"iss": iss, "sub": sub, "identity": f"{iss}/{sub}" if iss and sub else sub}


def audit_identity_snapshot(userinfo, realm=None):
    """Return audit_identity() plus the identifying attributes asserted at authentication time.

    Used only by events that record the outcome of an authentication at the IdP, accepted or
    rejected, so that personal information is written once per authentication; all other events
    carry audit_identity() and join back to the snapshot through session_id. The attributes are the values the IdP
    asserted at that moment, which may differ from the subject's current values. Linked
    identities come from the realm's augmentation provider. When AUDIT_INCLUDE_PII is false the
    snapshot reduces to audit_identity().
    """
    fields = audit_identity(userinfo, realm)
    if not _include_pii():
        return fields
    userinfo = userinfo or {}
    claim_map = _claim_map(realm)
    for claim in PII_CLAIMS:
        fields[claim] = resolve_claim(userinfo, claim_map, claim)
    fields["identities"] = _linked_identities(userinfo, realm)
    return fields
