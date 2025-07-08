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
from datetime import datetime
from zoneinfo import ZoneInfo
from tzlocal import get_localzone_name
from flask import Blueprint, request, jsonify, redirect, abort, current_app
from ..api.util import get_current_session, get_realm, get_effective_scopes, generate_nonce, \
    get_augmentation_provider, revoke_tokens, strtobool
from ..telemetry import audit_event

logger = logging.getLogger(__name__)

device_blueprint = Blueprint("device", __name__)

DEVICE_TTL = 600  # 10 minutes

@device_blueprint.route("/device/start", methods=["POST"])
def start_device_flow():
    store = current_app.config["SESSION_STORE"]
    realm = get_realm(request.args.get("realm"))
    refresh = request.args.get("refresh")
    refresh = bool(strtobool(refresh)) if refresh is not None else False

    device_code = str(uuid.uuid4().hex)
    user_code = str(uuid.uuid4())[:8].upper()
    flow = {
        "user_code": user_code,
        "verified": False,
        "issued_at": time.time(),
        "expires_at": time.time() + DEVICE_TTL,
        "session_key": None,
        "realm": realm,
        "refresh":refresh
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
    state = f"{device_code}"
    nonce = generate_nonce()
    store.store_nonce(state, nonce)

    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    client = factory.get_client(realm, native_client=True)
    redirect_uri = f"{current_app.config['BASE_URL']}/device/callback"

    auth_url, auth_state, code_verifier = client.create_authorization_url(
        use_pkce=current_app.config.get("ENABLE_PKCE", True),
        is_device=True,
        state=state,
        nonce=nonce,
        redirect_uri=redirect_uri,
        access_type="offline"
    )
    if code_verifier is not None:
        store.store_pkce_verifier(auth_state, code_verifier)

    return redirect(auth_url)

@device_blueprint.route("/device/callback", methods=["GET"])
def device_callback():
    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        abort(400, description="Invalid callback")

    device_code = state
    store = current_app.config["SESSION_STORE"]
    flow = store.get_device_flow(device_code)
    if not flow:
        abort(404, description="Device code not found or expired")

    realm = flow.get("realm", "default")
    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    client = factory.get_client(realm, native_client=True)

    redirect_uri = f"{current_app.config['BASE_URL']}/device/callback"
    code_verifier = store.get_pkce_verifier(state)
    if current_app.config.get("ENABLE_PKCE", True) and not code_verifier:
        abort(400, "Missing PKCE verifier")
    tokens = client.exchange_code_for_tokens(code, redirect_uri, code_verifier)
    store.delete_pkce_verifier(state)
    scopes_granted = tokens.get("scope", [])
    offline_granted = "refresh_token" in tokens

    # Validate nonce and token claims
    nonce = store.get_nonce(state)
    if not nonce:
        abort(400, description="Missing or expired nonce")
    try:
        userinfo = client.validate_id_token(tokens["id_token"], nonce)
    except Exception as e:
        abort(400, description=f"Unable to validate id_token: {e}")
    finally:
        store.delete_nonce(state)

    # Determine refresh expiration
    now = time.time()
    refresh_expires_in = tokens.get("refresh_expires_in")
    # 0 generally indicates "no expiry" (dubious) and None isn't helpful, so fall back to the configured value or default
    if not refresh_expires_in:
        refresh_expires_at = (
                now + (current_app.config.get("MAX_REFRESH_TOKEN_LIFETIME", 14) * 86400))  # default to 14 days
    else:
        refresh_expires_at = now + refresh_expires_in

    # Augment the session, if applicable
    provider = get_augmentation_provider(realm)
    # look for additional tokens in the response
    additional_tokens = provider.process_additional_tokens(tokens, now)
    # possibly get additional groups using external tokens or other means (e.g. Globus)
    provider.enrich_userinfo(userinfo, additional_tokens)

    metadata = {
        "device_session": True,
        "allow_automatic_refresh": flow.get("refresh", False),
        "offline_access_granted": offline_granted,
        "refresh_expires_at": refresh_expires_at,
        "token_expires_at": tokens.get("expires_at")
    }

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
        additional_tokens=additional_tokens
    )

    flow["verified"] = True
    flow["session_key"] = session_key
    store.set_device_flow(device_code, flow, ttl=DEVICE_TTL)

    sub = userinfo.get("sub")
    user = userinfo.get("email")
    audit_event("device_login",
                session_id=session_id,
                user=user,
                sub=sub,
                scopes=get_effective_scopes(session_data),
                realm=realm,
                offline_access=offline_granted,
                refresh_expires_at=datetime.fromtimestamp(refresh_expires_at,
                                                          tz=ZoneInfo(get_localzone_name())).isoformat())
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
        abort(400, "session lost (timed out or expired)")

    store.delete_device_flow(device_code)

    return jsonify({
        "access_token": flow["session_key"],
        "token_type": "Bearer",
        "expires_in": session.expires_at - time.time()
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