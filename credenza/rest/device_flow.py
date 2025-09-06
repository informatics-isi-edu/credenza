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
import uuid
import time
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, redirect, abort, current_app, g
from ..api.util import get_current_session, get_realm, get_effective_scopes, generate_nonce, augment_session, \
    revoke_tokens, strtobool
from ..telemetry import audit_event

logger = logging.getLogger(__name__)

device_blueprint = Blueprint("device", __name__)

DEVICE_TTL = 600  # 10 minutes

@device_blueprint.route("/device/start", methods=["POST"])
def start_device_flow():
    store = current_app.config["SESSION_STORE"]
    realm = current_app.config["DEFAULT_REALM"]
    refresh = request.args.get("refresh")
    refresh = bool(strtobool(refresh)) if refresh is not None else False

    device_code = str(uuid.uuid4().hex)
    user_code = str(uuid.uuid4())[:8].upper()
    poll_interval = current_app.config.get("DEVICE_POLL_INTERVAL", 3)
    redirect_uri = f"{current_app.config['BASE_URL']}/device/callback"
    flow = {
        "user_code": user_code,
        "verified": False,
        "interval": poll_interval,
        "issued_at": time.time(),
        "expires_at": time.time() + DEVICE_TTL,
        "session_key": None,
        "realm": realm,
        "refresh":refresh,
        "redirect_uri":  redirect_uri
    }
    store.set_device_flow(device_code, flow, ttl=DEVICE_TTL)
    store.set_usercode_mapping(user_code, device_code, ttl=DEVICE_TTL)

    return jsonify({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": f"{current_app.config['BASE_URL']}/device/verify/{user_code}",
        "interval": current_app.config.get("DEVICE_POLL_INTERVAL", 3),
        "expires_in": DEVICE_TTL
    })

@device_blueprint.route("/device/verify/<user_code>", methods=["GET"])
def verify_device(user_code):
    store = current_app.config["SESSION_STORE"]
    device_code = store.get_device_code_for_usercode(user_code)
    if not device_code:
        abort(404, description="Invalid user code")
    store.delete_usercode_mapping(user_code)

    flow = store.get_device_flow(device_code)
    if not flow:
        abort(404, description="Expired or invalid flow")

    realm = flow.get("realm", "default")
    redirect_uri = flow.get("redirect_uri")
    state = f"{device_code}"
    nonce = generate_nonce()

    profile = current_app.config["OIDC_IDP_PROFILES"].get(get_realm(realm), {})
    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    try:
        client = factory.get_client(realm, native_client=True)
    except Exception as e:
        abort(502, description=f"OIDC client init failed: {e}")

    request_offline_access_scope = profile.get("request_offline_access_scope_in_device_flow", True)
    auth_url, auth_state, code_verifier = client.create_authorization_url(
        use_pkce=current_app.config.get("ENABLE_PKCE", True),
        request_offline_access_scope=request_offline_access_scope,
        state=state,
        nonce=nonce,
        redirect_uri=redirect_uri,
        access_type="offline"
    )

    flow.update({
        "nonce": nonce,
        "code_verifier": code_verifier,
        "scope": client.scope
    })
    store.set_device_flow(device_code, flow, ttl=DEVICE_TTL)

    return redirect(auth_url)

@device_blueprint.route("/device/callback", methods=["GET"])
def device_callback():
    err = request.args.get("error")
    if err:
        desc = request.args.get("error_description") or err
        abort(400, description=f"Authorization error: {desc}")

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        abort(400, description="Invalid callback")

    device_code = state
    store = current_app.config["SESSION_STORE"]
    flow = store.get_device_flow(device_code)
    if not flow:
        abort(404, description="Device code not found or expired")

    if flow.get("verified"):
        abort(409, "Device already verified")

    realm = flow.get("realm", "default")
    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    try:
        client = factory.get_client(realm, native_client=True)
    except Exception as e:
        abort(502, description=f"OIDC client init failed: {e}")

    code_verifier = flow.get("code_verifier")
    if current_app.config.get("ENABLE_PKCE", True) and not code_verifier:
        abort(400, "Missing PKCE verifier")

    redirect_uri = flow.get("redirect_uri")
    try:
        tokens = client.exchange_code_for_tokens(code, redirect_uri, code_verifier)
    except Exception as e:
        abort(502, description=f"Token exchange failed: {e}")
    scopes_granted = tokens.get("scope", flow.get("scope"))
    offline_granted = "refresh_token" in tokens

    # Validate nonce and token claims
    nonce = flow.get("nonce")
    if not nonce:
        abort(400, description="Missing or expired nonce")
    try:
        userinfo = client.validate_id_token(tokens["id_token"], nonce)
    except Exception as e:
        store.set_device_flow(device_code, flow, ttl=60)  # shorten TTL
        abort(400, description=f"Unable to validate id_token: {e}")

    # Determine refresh expiration
    now = time.time()
    refresh_expires_in = tokens.get("refresh_expires_in")
    # 0 generally indicates "no expiry" (dubious) and None isn't helpful, so fall back to the configured value or default
    if not refresh_expires_in:
        refresh_expires_at = (
                now + (current_app.config.get("MAX_REFRESH_TOKEN_LIFETIME", 14) * 86400))  # default to 14 days
    else:
        refresh_expires_at = now + refresh_expires_in

    metadata = {
        "device_session": True,
        "allow_automatic_refresh": flow.get("refresh", False),
        "offline_access_granted": offline_granted,
        "refresh_expires_at": refresh_expires_at,
        "token_expires_at": tokens.get("expires_at")
    }

    # Augment the session, if applicable
    userinfo, additional_tokens = augment_session(tokens, realm, userinfo, metadata)

    session_id = store.generate_session_id()
    session_key, session_data = store.create_session(
        session_id=session_id,
        access_token=tokens.get("access_token"),
        id_token=tokens.get("id_token"),
        refresh_token=tokens.get("refresh_token"),
        scopes=scopes_granted,
        userinfo=userinfo,
        realm=realm,
        metadata=metadata,
        additional_tokens=additional_tokens,
        expires_at=refresh_expires_at
    )

    flow.update({"verified": True, "session_key": session_key, "nonce": None, "code_verifier": None})
    store.set_device_flow(device_code, flow, ttl=DEVICE_TTL)

    if metadata.get("augmentation_deferred", False):
        g.session_key = session_key
        userinfo, additional_tokens = augment_session(tokens, realm, userinfo, metadata)
        metadata.pop("augmentation_deferred", None)
        session_data.userinfo = userinfo
        session_data.metadata = metadata
        session_data.additional_tokens = additional_tokens
        store.update_session(session_id, session_data)

    sub = userinfo.get("sub")
    user = userinfo.get("email")
    audit_event("device_login",
                session_id=session_id,
                user=user,
                sub=sub,
                scopes=get_effective_scopes(session_data),
                realm=realm,
                offline_access=offline_granted,
                refresh_expires_at=datetime.fromtimestamp(refresh_expires_at, timezone.utc).isoformat())
    logger.info(f"Device login successful for user {user} ({sub}) with session id {session_id} on realm {realm}")

    return "Device authorization complete. You may return to the device."

@device_blueprint.route("/device/token", methods=["POST"])
def poll_for_token():
    data = request.get_json()
    device_code = data.get("device_code")
    if not device_code:
        abort(400, description="Missing device_code")

    store = current_app.config["SESSION_STORE"]
    flow = store.get_device_flow(device_code)
    if not flow:
        abort(400, "expired token")

    now = time.time()
    last_poll = flow.get("last_poll_at", 0)
    interval = flow.get("interval", 0)
    if now < last_poll + interval:
        abort(429, description="slow_down")
    flow["last_poll_at"] = now
    store.set_device_flow(device_code, flow, store.get_device_flow_ttl(device_code))

    if not flow.get("verified") or not flow.get("session_key"):
        return jsonify({"error": "authorization_pending"}), 403

    sid, session = store.get_session_by_session_key(flow["session_key"])
    if not session:
        abort(400, "session lost (flow timed out or session expired)")

    store.delete_device_flow(device_code)

    return jsonify({
        "access_token": flow["session_key"],
        "token_type": "Bearer",
        "expires_in":  max(0, int(session.expires_at - time.time()))
    })

@device_blueprint.route("/device/logout", methods=["POST"])
def device_logout():
    sid, session = get_current_session()
    store = current_app.config["SESSION_STORE"]

    # Confirm this is a device session
    is_device = session.session_metadata.system.get("device_session")
    if not is_device:
        abort(403, description="Not a device session")

    revoke_tokens(sid, session)

    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    store.delete_session(sid)

    audit_event("device_logout", session_id=sid, user=user, sub=sub)
    logger.info(f"Device logout for user {user} ({sub}) with session id {sid} on realm {realm}")

    return jsonify({"status": "logged out"})
