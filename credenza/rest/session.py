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
from ..api.util import get_current_session, get_effective_scopes, make_json_response, refresh_access_token, \
    refresh_additional_tokens, revoke_tokens, get_augmentation_provider, strtobool, is_browser_client
from ..api.session.storage.session_store import SessionData
from ..telemetry import audit_event

logger = logging.getLogger(__name__)

session_blueprint = Blueprint("session", __name__)

@session_blueprint.route("/whoami", methods=["GET"])
def whoami():
    sid, session = get_current_session()
    return make_json_response(session.userinfo)

@session_blueprint.route("/session", methods=["GET", "PUT"])
def get_session():
    try:
        upstream = strtobool(str(request.args.get("refresh_upstream", False)))
    except ValueError:
        upstream = False
    if current_app.config.get("ENABLE_LEGACY_API", False):
        upstream = True

    sid, session = get_current_session()
    store = current_app.config["SESSION_STORE"]
    now = time.time()

    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm

    if request.method == "PUT":
        # Extend session lifetime
        session.updated_at = now
        session.expires_at = now + store.ttl

        # Enforce max refreshable lifetime
        refresh_expires_at = session.session_metadata.system.get("refresh_expires_at")
        if refresh_expires_at and now > refresh_expires_at:
            store.delete_session(sid)
            audit_event("refresh_expired", session_id=sid)
            abort(401, "Session has expired and can no longer be refreshed")

        if upstream:
            # Potentially refresh our access token from upstream, if we've got a refresh token to do so
            refresh_access_token(sid, session)
            # Potentially refresh additional access tokens (if present) from upstream, and we've got refresh tokens for them
            refresh_additional_tokens(sid, session)
            # Enrich userinfo, if applicable
            provider = get_augmentation_provider(realm)
            provider.enrich_userinfo(session.userinfo, session.additional_tokens)

        store.update_session(sid, session)
        audit_event("session_extended", session_id=sid, user=user, sub=sub, realm=realm)

    response = make_session_response(sid, session)
    return make_json_response(response)

@session_blueprint.route("/session", methods=["PATCH"])
def patch_session():
    sid, _ = get_current_session()
    patch = request.get_json()
    if not isinstance(patch, dict):
        abort(400, "Expected JSON object")

    store = current_app.config["SESSION_STORE"]
    store.tag_session_metadata(sid, patch, scope="user")
    audit_event("session_metadata_patch", session_id=sid, metadata=patch)
    return jsonify({"status": "updated", "patched": patch})

@session_blueprint.route("/session", methods=["DELETE"])
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

def _claim_from_resolver(session, key, fallback=None):
    resolver = current_app.config.get("CLAIM_RESOLVER")
    if resolver:
        return resolver.claim(session.userinfo, key, session.realm, fallback)
    # fallback if resolver not configured
    return session.userinfo.get(key, fallback)


def make_session_response(sid, session: SessionData):
    response = {}
    store = current_app.config["SESSION_STORE"]

    if current_app.config.get("ENABLE_LEGACY_API", False):
        issuer = _claim_from_resolver(session, "iss")
        user_id = _claim_from_resolver(session, "id",
                                       session.userinfo.get("sub", session.userinfo.get("userid")))
        preferred_username = _claim_from_resolver(session, "preferred_username",
                                                  session.userinfo.get("username") or session.userinfo.get("name"))
        full_name = _claim_from_resolver(session, "full_name", session.userinfo.get("name"))
        email = _claim_from_resolver(session, "email", session.userinfo.get("email"))

        client = {
            "id": f"{issuer}/{user_id}" if issuer and user_id else session.userinfo.get("sub"),
            "display_name": preferred_username,
            "full_name": full_name,
            "email": email,
        }

        identity_set = session.userinfo.get("identity_set", session.userinfo.get("identity_set_detail"))
        identities = []
        if identity_set:
            for ident in identity_set:
                sub = ident.get("sub") or ident.get("id") or ident.get("userid")
                if sub and issuer:
                    identities.append(f"{issuer}/{sub}")
        client["identities"] = identities
        response["client"] = client

        # format "attributes" array
        attributes = [client]
        # Use resolver-backed groups so non-standard keys like 'cognito:groups' map correctly
        groups_claim = _claim_from_resolver(session, "groups", []) or []
        groups = []
        for group in groups_claim:
            if isinstance(group, dict):
                groups.append(group)
            elif isinstance(group, str):
                groups.append({"id": group, "display_name": group})
        attributes.extend(groups)
        response["attributes"] = attributes

        response["since"] = datetime.fromtimestamp(session.created_at, timezone.utc).isoformat()
        response["expires"] = datetime.fromtimestamp(session.expires_at, timezone.utc).isoformat()
        response["seconds_remaining"] = store.get_ttl(sid)
    else:
        preferred_username = _claim_from_resolver(session, "preferred_username", session.userinfo.get("name"))
        full_name = _claim_from_resolver(session, "full_name", session.userinfo.get("name"))
        email = _claim_from_resolver(session, "email", session.userinfo.get("email"))
        email_verified = _claim_from_resolver(session, "email_verified", "unknown")
        user_id = _claim_from_resolver(session, "id", session.userinfo.get("sub", session.userinfo.get("userid")))
        iss = _claim_from_resolver(session, "iss", session.userinfo.get("iss"))
        aud = _claim_from_resolver(session, "aud", session.userinfo.get("aud"))
        groups = _claim_from_resolver(session, "groups", []) or []
        roles = _claim_from_resolver(session, "roles", []) or []

        # normalize email_verified to bool if it arrives as a string
        if isinstance(email_verified, str):
            lv = email_verified.strip().lower()
            if lv in ("true", "1", "yes"):
                email_verified = True
            elif lv in ("false", "0", "no"):
                email_verified = False

        response.update(
            {
                "preferred_username": preferred_username,
                "full_name":          full_name,
                "email":              email,
                "email_verified":     email_verified,
                "id":                 user_id,
                "iss":                iss,
                "aud":                aud,
                "groups":             groups,
                "roles":              roles,
                "scopes":             get_effective_scopes(session),
                "metadata":           session.session_metadata.to_dict(),
                "created_at":         datetime.fromtimestamp(session.created_at, timezone.utc).isoformat(),
                "updated_at":         datetime.fromtimestamp(session.updated_at, timezone.utc).isoformat(),
                "expires_at":         datetime.fromtimestamp(session.expires_at, timezone.utc).isoformat(),
                "seconds_remaining":  store.get_ttl(sid),
            }
        )
    return response
