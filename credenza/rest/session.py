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
from datetime import datetime
from zoneinfo import ZoneInfo
from tzlocal import get_localzone_name
from flask import Blueprint, request, redirect, jsonify, abort, current_app
from credenza.api.util import get_current_session, get_effective_scopes, make_json_response, refresh_access_token, \
    refresh_additional_tokens
from credenza.api.session.storage.session_store import SessionData
from credenza.telemetry import audit_event

logger = logging.getLogger(__name__)

session_blueprint = Blueprint("session", __name__)

@session_blueprint.route("/whoami", methods=["GET"])
def whoami():
    sid, session = get_current_session()
    return make_json_response(session.userinfo)

@session_blueprint.route("/session", methods=["GET", "PUT"])
def get_session():
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

        # Potentially refresh our access token from upstream, if we've got a refresh token to do so
        refresh_access_token(sid, session)
        # Potentially refresh additional access tokens (if present) from upstream, and we've got refresh tokens for them
        refresh_additional_tokens(sid, session)

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

    store.delete_session(sid)
    audit_event("logout", session_id=sid, user=user, sub=sub, realm=realm)

    resp = jsonify({"status": "logged out"})
    resp.set_cookie(current_app.config["COOKIE_NAME"], "", expires=0)
    return resp

def make_session_response(sid, session: SessionData):
    response = {}
    store = current_app.config["SESSION_STORE"]

    if current_app.config.get("ENABLE_LEGACY_API", False):
        # format "client" object
        client = {}
        issuer = session.userinfo.get("iss")
        client["id"] = issuer + "/" + session.userinfo.get("sub")
        client["display_name"] = session.userinfo.get("preferred_username", session.userinfo.get("username"))
        client["full_name"] = session.userinfo.get("name")
        client["email"] = session.userinfo.get("email")

        identity_set = session.userinfo.get('identity_set', session.userinfo.get('identity_set_detail'))
        identities = []
        if identity_set is not None:
            for ident in identity_set:
                full_id = issuer + '/' + ident["sub"]
                identities.append(full_id)
        client["identities"] = identities
        response["client"] = client

        # format "attributes" array
        attributes = [client]
        groups = []
        for group in session.userinfo.get("groups", []):
            if not isinstance(group, dict):
                if isinstance(group, str):
                    groups.append({"id": group, "display_name": group})
            elif isinstance(group, dict):
                groups.append(group)
        attributes.extend(groups)
        response["attributes"] = attributes

        response["since"] = datetime.fromtimestamp(session.created_at,
                                                   tz=ZoneInfo(get_localzone_name())).isoformat()
        response["expires"] = datetime.fromtimestamp(session.expires_at,
                                                     tz=ZoneInfo(get_localzone_name())).isoformat()
        response["seconds_remaining"] = store.get_ttl(sid)
    else:
        response.update(
            {
                "preferred_username": session.userinfo.get("preferred_username"),
                "full_name": session.userinfo.get("name"),
                "email": session.userinfo.get("email"),
                "email_verified": session.userinfo.get("email_verified", "unknown"),
                "id": session.userinfo.get("sub", session.userinfo.get("userid")),
                "iss": session.userinfo.get("iss"),
                "aud": session.userinfo.get("aud"),
                "groups": session.userinfo.get("groups", []),
                "roles": session.userinfo.get("roles", []),
                "scopes": get_effective_scopes(session),
                "metadata": session.session_metadata.to_dict(),
                "created_at": datetime.fromtimestamp(session.created_at,
                                                     tz=ZoneInfo(get_localzone_name())).isoformat(),
                "updated_at": datetime.fromtimestamp(session.updated_at,
                                                     tz=ZoneInfo(get_localzone_name())).isoformat(),
                "expires_at": datetime.fromtimestamp(session.expires_at,
                                                     tz=ZoneInfo(get_localzone_name())).isoformat(),
                "seconds_remaining": store.get_ttl(sid)
            }
        )
    return response