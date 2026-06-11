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
import time
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, redirect, jsonify, abort, current_app
from .helpers import make_json_response, perf_logged
from ..telemetry import audit_event
from ..api.common.claim_mapper import resolve_claim, get_claim_map_for_realm
from ..api.session.storage.session_store import SessionData, SessionType
from ..api.common.util import (
    get_current_session,
    get_effective_scopes,
    get_request_resource_args,
    get_augmentation_provider,
    refresh_access_token,
    refresh_additional_tokens,
    revoke_tokens,
    strtobool
)

logger = logging.getLogger(__name__)

session_blueprint = Blueprint("session", __name__)

@session_blueprint.route("/whoami", methods=["GET"])
@perf_logged(warn_ms=1000)
def whoami():
    sid, session = get_current_session()
    response = {
        "remote_addr": request.remote_addr,
        "xff": request.headers.get("X-Forwarded-For"),
        "proto": request.headers.get("X-Forwarded-Proto")
    }
    response.update(session.userinfo)
    return make_json_response(response)


@session_blueprint.route("/session", methods=["GET", "PUT"])
@perf_logged(warn_ms=1000, include_query=True)
def get_session():

    try:
        upstream = strtobool(str(request.args.get("refresh_upstream", False)))
    except ValueError:
        upstream = False
    if current_app.config.get("ENABLE_LEGACY_API", False):
        upstream = True

    sid, session = get_current_session()
    store = current_app.config["SESSION_STORE"]
    now = int(time.time())

    realm = session.realm
    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email") \
        if not session.is_service() else session.userinfo.get("name","service")

    # Accept multiple resource hints via repeated query params: ?resource=A&resource=B
    req_resources = get_request_resource_args(request.args.getlist("resource"))

    if session.is_service():
        # Resource binding for service/M2M tokens at introspection.
        #   Rationale: issuance != proper use. This prevents cross-service replay by requiring that
        #   at least one requested resource matches the token's declared resources.
        res_claim = set(session.allowed_resources)
        if not res_claim:
            audit_event(
                "service_session_resource_misconfig",
                session_id=sid,
                realm=realm,
                reason="empty_resource_in_session",
            )
            abort(403, "empty_resource_in_session")

        if not req_resources:
            audit_event(
                "service_session_resource_denied",
                session_id=sid,
                realm=realm,
                requested_resources=[],
                token_resources=sorted(res_claim),
                reason="missing_resource_param",
            )
            abort(403, "missing_resource_param")

        if not (set(req_resources) & res_claim):
            audit_event(
                "service_session_resource_denied",
                session_id=sid,
                realm=realm,
                requested_resources=req_resources,
                token_resources=sorted(res_claim),
                reason="no_resource_intersection",
            )
            abort(403, "no_resource_intersection")

        # Successful service resource check
        audit_event(
            "service_session_resource_ok",
            session_id=sid,
            realm=realm,
            requested_resources=req_resources,
            token_resources=sorted(res_claim),
        )

    elif session.allowed_resources:
        # Resource binding for non-service sessions that carry allowed_resources
        # (e.g., user sessions issued via authorization_code flow, or derived sessions).
        # In legacy mode: skip unless LEGACY_DEFAULT_RESOURCE is configured.
        # In non-legacy mode: enforce only when the caller provides a resource param.
        if req_resources:
            res_claim = set(session.allowed_resources)
            if not (set(req_resources) & res_claim):
                audit_event(
                    "session_resource_denied",
                    session_id=sid,
                    realm=realm,
                    requested_resources=req_resources,
                    token_resources=sorted(res_claim),
                    reason="no_resource_intersection",
                )
                abort(403, "no_resource_intersection")
            audit_event(
                "session_resource_ok",
                session_id=sid,
                realm=realm,
                requested_resources=req_resources,
                token_resources=sorted(res_claim),
            )

    if request.method == "PUT":

        if session.is_service() or session.is_derived():
            max_ttl = session.session_ttl
            now_i = int(now)

            # Clamp final expiry to session.session_ttl if configured.
            # Derived sessions are non-extendable by design; so we allow a PUT on a derived session
            # to receive a valid session response without triggering the can_extend() guard.
            if max_ttl > 0:
                cap = now_i + max_ttl
                if session.expires_at > cap:
                    session.expires_at = cap
                    session.session_ttl = 0  # do not extend expires_at in update_session()
                    audit_event(
                        "service_session_ttl_clamped",
                        session_id=sid,
                        realm=realm,
                        clamped_expires_at=datetime.fromtimestamp(cap, timezone.utc).isoformat(),
                        max_session_ttl_seconds=max_ttl)
        else:
            if not session.can_extend():
                audit_event("session_not_extendable",
                            session_id=sid,
                            user=user,
                            sub=sub,
                            realm=realm,
                            expires_at=datetime.fromtimestamp(session.expires_at, timezone.utc).isoformat())
                abort(403, "session cannot be extended")

            # enforce max refreshable lifetime for user sessions
            session_expiry_threshold = current_app.config.get("SESSION_EXPIRY_THRESHOLD", 300)
            absolute_expires_at = session.absolute_expires_at
            if absolute_expires_at and now > (absolute_expires_at - session_expiry_threshold):
                revoke_tokens(sid, session)
                store.delete_session(sid)
                audit_event("session_absolute_lifetime_expired", session_id=sid)
                abort(401, "session_absolute_lifetime_expired")

            if upstream and session.can_refresh_upstream():
                # Potentially refresh our access token from upstream, if we've got a refresh token to do so
                refresh_access_token(sid, session)
                # Potentially refresh additional access tokens (if present) from upstream, and we've got refresh tokens for them
                refresh_additional_tokens(sid, session)
                # Enrich userinfo, if applicable
                provider = get_augmentation_provider(realm)
                provider.enrich_userinfo(session.userinfo, session.additional_tokens)

        skey, session_data = store.update_session(sid, session)
        audit_event("session_updated",
                    session_id=sid,
                    user=user,
                    sub=sub,
                    realm=realm,
                    expires_at=datetime.fromtimestamp(session_data.expires_at, timezone.utc).isoformat())

    response = make_session_response(sid, session)
    return make_json_response(response)


# @session_blueprint.route("/session", methods=["PATCH"])
# @perf_logged(warn_ms=1000)
# def patch_session():
#     sid, session = get_current_session()
#     patch = request.get_json()
#     if not isinstance(patch, dict):
#         abort(400, "Expected JSON object")
#
#     if not session.is_primary():
#         abort(403, "Only user sessions are allowed to PATCH")
#
#     store = current_app.config["SESSION_STORE"]
#     store.tag_session_metadata(sid, patch, scope="user")
#     audit_event("session_metadata_patch", session_id=sid, metadata=patch)
#     return jsonify({"status": "updated", "patched": patch})


@session_blueprint.route("/session", methods=["DELETE"])
@perf_logged(warn_ms=1000)
def delete_session():
    if current_app.config.get("ENABLE_LEGACY_API", False):
        return redirect(f"{current_app.config['BASE_URL']}/logout", 303)

    sid, session = get_current_session()
    store = current_app.config["SESSION_STORE"]

    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm

    revoke_tokens(sid, session)

    store.delete_session(sid)
    audit_event("logout", session_id=sid, user=user, sub=sub, realm=realm)

    resp = jsonify({"status": "logged out"})
    resp.set_cookie(current_app.config["COOKIE_NAME"], "", expires=0)
    return resp


def _claim(session, key, fallback=None, *, listify=False):
    realm = session.realm or "default"
    claim_map = get_claim_map_for_realm(realm=realm, realm_maps= current_app.config.get("IDP_CLAIM_MAPS"))
    return resolve_claim(session.userinfo, claim_map, key, fallback, listify=listify)


def _format_attributes(claim_names: list, attributes: list, session: SessionData) -> list:
    for claim_name in claim_names:
        claim = _claim(session, claim_name, session.userinfo.get(claim_name, []), listify=True)
        attrs = []
        for attr in claim:
            if isinstance(attr, dict):
                attrs.append(attr)
            elif isinstance(attr, str):
                attrs.append({"id": attr, "display_name": attr})
        attributes.extend(attrs)

    return attributes


def _canonical_identities(session: SessionData) -> dict:
    """Build the canonical identities map for a session at render time.

    Linked-identity canonicalization is a pure transform of claims already in
    userinfo (no I/O), so it is computed on demand via the realm's augmentation
    provider rather than persisted into the session. Returns a dict keyed by
    canonical identity id whose values hold per-identity detail.
    """
    provider = get_augmentation_provider(session.realm)
    return provider.build_identities(session.userinfo) if provider else {}


def make_session_response(sid, session: SessionData):
    response = {}
    store = current_app.config["SESSION_STORE"]
    canonical_identities = _canonical_identities(session)

    if current_app.config.get("ENABLE_LEGACY_API", False):
        issuer =             _claim(session, "iss", session.userinfo.get("iss"))
        sub =                _claim(session, "sub", session.userinfo.get("sub"))
        full_name =          _claim(session, "full_name", session.userinfo.get("name"))
        email =              _claim(session, "email", session.userinfo.get("email"))
        preferred_username = _claim(session, "preferred_username", session.userinfo.get("preferred_username"))

        # format "client" object
        client_id = f"{issuer}/{sub}" if issuer else sub
        client = {"id": client_id,
                  "display_name": preferred_username,
                  "full_name": full_name,
                  "email": email}

        # The legacy webauthn contract is a flat list of identity-id strings, so
        # default to the ids (the keys of the canonical identities map) to avoid
        # breaking existing consumers. Deployments that want the full detail
        # objects can opt in via LEGACY_IDENTITY_DETAIL.
        if current_app.config.get("LEGACY_IDENTITY_DETAIL", False):
            client["identities"] = canonical_identities
        else:
            client["identities"] = list(canonical_identities.keys())
        response["client"] = client

        # format "attributes" array
        attributes = [client]
        _format_attributes(["groups", "roles", "resources", "scopes", "claims"], attributes, session)
        response["attributes"] = attributes

        response["since"] = datetime.fromtimestamp(session.created_at, timezone.utc).isoformat()
        response["expires"] = datetime.fromtimestamp(session.expires_at, timezone.utc).isoformat()
        response["seconds_remaining"] = store.get_ttl(sid)
    else:
        preferred_username = _claim(session, "preferred_username", session.userinfo.get("preferred_username"))
        full_name =          _claim(session, "full_name", session.userinfo.get("name"))
        email =              _claim(session, "email", session.userinfo.get("email"))
        email_verified =     _claim(session, "email_verified", session.userinfo.get("email_verified", "unknown"))
        sub =                _claim(session, "sub", session.userinfo.get("sub"))
        iss =                _claim(session, "iss", session.userinfo.get("iss"))
        aud =                _claim(session, "aud", session.userinfo.get("aud"))
        groups =             _claim(session, "groups", session.userinfo.get("groups", []), listify=True)
        roles =              _claim(session, "roles", session.userinfo.get("roles", []), listify=True)
        userid =             _claim(session, "userid", session.userinfo.get("userid"))

        # normalize email_verified if it arrives as a string
        if isinstance(email_verified, str):
            lv = email_verified.strip().lower()
            if lv in ("1", "yes"):
                email_verified = "true"
            elif lv in ("0", "no"):
                email_verified = "false"

        _id = f"{iss}/{sub}" if iss else sub

        response.update(
            {
                "preferred_username": preferred_username,
                "full_name":          full_name,
                "email":              email,
                "email_verified":     email_verified,
                "sub":                sub,
                "iss":                iss,
                "aud":                aud,
                "id":                 _id,
                "userid":             userid,
                "groups":             groups,
                "roles":              roles,
                "identities":         canonical_identities,
                "scopes":             get_effective_scopes(session),
                "resources":          session.allowed_resources,
                "metadata":           session.session_metadata.to_dict(),
                "created_at":         datetime.fromtimestamp(session.created_at, timezone.utc).isoformat(),
                "updated_at":         datetime.fromtimestamp(session.updated_at, timezone.utc).isoformat(),
                "expires_at":         datetime.fromtimestamp(session.expires_at, timezone.utc).isoformat(),
                "seconds_remaining":  store.get_ttl(sid),
            }
        )
        if userid is None:
            del response["userid"]

    return response
