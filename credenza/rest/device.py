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
from flask import Blueprint, request, jsonify, redirect, abort, current_app, g, render_template_string
from secrets import token_hex
from .helpers import perf_logged, adapter_authenticate, GrantType, ip_rate_limited
from ..telemetry import audit_event
from ..api.common.crypto import generate_nonce
from ..api.common.errors import OAuthError
from ..api.session.storage.session_store import SessionType
from ..api.auth.client.adapters.adapter import ProofContext
from ..api.common.util import (
    get_realm,
    get_effective_scopes,
    get_request_resource_args,
    augment_session,
    enrich_userinfo_from_endpoint,
    get_missing_scope_claims,
    extract_jwt_txn,
    check_acr,
    strtobool
)

logger = logging.getLogger(__name__)

device_blueprint = Blueprint("device", __name__)

DEVICE_FLOW_TTL = 600  # default: 10 minutes


@device_blueprint.route("/device_authorization", methods=["POST"]) # RFC 8628
@device_blueprint.route("/device/start", methods=["POST"])
@perf_logged(warn_ms=1000)
@ip_rate_limited()
def start_device_flow():
    store = current_app.config["SESSION_STORE"]
    realm = current_app.config["DEFAULT_REALM"]
    # Default allowed_resources applied when no registered client record provides an explicit policy:
    #   - ENABLE_LEGACY_API=True: seed with LEGACY_DEFAULT_RESOURCE (covers no-registry deployments
    #     and unregistered clients when ALLOW_UNREGISTERED_CLIENTS is also set).
    #   - Otherwise: empty -- registered client policy or explicit resource request required.
    allowed_resources = [current_app.config.get("LEGACY_DEFAULT_RESOURCE")] if current_app.config.get(
        "ENABLE_LEGACY_API", False) else []

    # RFC 8628 compliance: require client_id and validate against registry when available.
    client_id = request.form.get("client_id") or request.args.get("client_id")
    client_registry = current_app.config.get("CLIENT_REGISTRY")

    if client_registry is not None:
        if not client_id:
            audit_event("device_authorization_missing_client_id")
            abort(400, description=OAuthError.INVALID_REQUEST)

        client_rec = client_registry.get(client_id)
        allow_unregistered = current_app.config.get("ALLOW_UNREGISTERED_CLIENTS", False)

        if client_rec is not None and not client_rec.enabled:
            audit_event("device_authorization_disabled_client", client_id=client_id)
            abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

        if client_rec is None and not allow_unregistered:
            audit_event("device_authorization_unknown_client", client_id=client_id)
            abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

        if client_rec is not None:
            # Registered client: enforce grant type, auth, scope, and resource policy.
            device_grant = GrantType.DEVICE_CODE
            if device_grant not in (client_rec.allowed_grant_types or []):
                audit_event("device_authorization_grant_type_denied",
                            client_id=client_id, grant_type=device_grant)
                abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

            # Confidential clients must authenticate.
            if not client_rec.public:
                proof_ctx = ProofContext(request.form.to_dict(flat=False), dict(request.headers))
                adapter_authenticate(proof_context=proof_ctx, client_rec=client_rec)

            # Validate requested scope against client's allowed_scopes.
            requested_scope = (request.form.get("scope") or "").strip()
            allowed_scopes = set(client_rec.allowed_scopes or [])
            if allowed_scopes and requested_scope:
                for s in requested_scope.split():
                    if s not in allowed_scopes:
                        audit_event("device_authorization_scope_denied",
                                    client_id=client_id, scope=s)
                        abort(400, description=OAuthError.INVALID_REQUEST)

            # Validate requested resources against client's allowed_resources.
            requested_resources = get_request_resource_args(request.form.getlist("resource"))
            allowed_resources_set = set(client_rec.allowed_resources or [])
            if allowed_resources_set and requested_resources:
                for r in requested_resources:
                    if r not in allowed_resources_set:
                        audit_event("device_authorization_resource_denied",
                                    client_id=client_id, resource=r)
                        abort(400, description=OAuthError.INVALID_TARGET)

            # Use the validated requested resources or fall back to client's allowed set.
            allowed_resources = requested_resources if requested_resources else list(client_rec.allowed_resources or [])

    refresh = request.form.get("refresh")
    refresh = bool(strtobool(refresh)) if refresh is not None else False

    device_code = token_hex(16)  # 128 bits
    user_code = token_hex(4).upper()  # 32 bits, 8 hex chars
    device_flow_ttl = current_app.config.get("DEVICE_FLOW_TTL", DEVICE_FLOW_TTL)
    poll_interval = current_app.config.get("DEVICE_POLL_INTERVAL", 3)
    redirect_uri = f"{current_app.config['BASE_URL']}/device/callback"
    flow = {
        "user_code": user_code,
        "verified": False,
        "interval": poll_interval,
        "issued_at": int(time.time()),
        "expires_at": int(time.time()) + device_flow_ttl,
        "session_key": None,
        "realm": realm,
        "refresh": refresh,
        "redirect_uri": redirect_uri,
        "allowed_resources": allowed_resources,
        "client_id": client_id,
    }
    store.set_device_flow(device_code, flow, ttl=device_flow_ttl)
    store.set_usercode_mapping(user_code, device_code, ttl=device_flow_ttl)

    return jsonify({
        "device_code": device_code,
        "user_code": user_code,
        "verification_uri": f"{current_app.config['BASE_URL']}/device/verify/{user_code}",
        "interval": poll_interval,
        "expires_in": device_flow_ttl
    })


@device_blueprint.route("/device/verify/<user_code>", methods=["GET"])
@ip_rate_limited()
def verify_device(user_code):
    store = current_app.config["SESSION_STORE"]
    device_code = store.consume_usercode_mapping(user_code)
    if not device_code:
        abort(404, description="Invalid user code")

    flow = store.get_device_flow(device_code)
    if not flow:
        # Defensive: user_code and device_flow are created with the same TTL, so both
        # should expire together. This branch is unlikely but guards against race
        # conditions, storage inconsistencies, or manual deletion of the device_flow.
        logger.warning(f"Device flow missing for valid user_code: user_code={user_code}, device_code={device_code}")
        abort(410, description="Device authorization expired. Please restart the device flow.")

    realm = flow.get("realm", "default")
    redirect_uri = flow.get("redirect_uri")
    state = f"{device_code}"
    nonce = generate_nonce()

    profile = current_app.config["OIDC_IDP_PROFILES"].get(get_realm(realm), {})
    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    try:
        client = factory.get_client(realm, native_client=True)
    except Exception as e:
        msg = "OIDC client init failed"
        logger.error(f"{msg}: {e}")
        abort(502, description=msg)

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
    store.set_device_flow(device_code, flow, ttl=current_app.config.get("DEVICE_FLOW_TTL", DEVICE_FLOW_TTL))

    return redirect(auth_url)


@device_blueprint.route("/device/callback", methods=["GET"])
@perf_logged(warn_ms=1000)
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
        msg = "OIDC client init failed"
        logger.error(f"{msg}: {e}")
        abort(502, description=msg)

    code_verifier = flow.get("code_verifier")
    if current_app.config.get("ENABLE_PKCE", True) and not code_verifier:
        abort(400, "Missing PKCE verifier")

    redirect_uri = flow.get("redirect_uri")
    try:
        tokens = client.exchange_code_for_tokens(code, redirect_uri, code_verifier)
    except Exception as e:
        msg = "Token exchange failed"
        logger.error(f"{msg}: {e}")
        abort(502, description=msg)
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
        msg = "Unable to validate id_token"
        logger.error(f"{msg}: {e}")
        abort(400, description=msg)

    # Fallback to IDP userinfo endpoint if the ID token is missing key claims.
    # Same logic as the browser login path -- opt out per realm with skip_userinfo_fallback: true.
    profile = current_app.config["OIDC_IDP_PROFILES"].get(realm, {})
    if not profile.get("skip_userinfo_fallback"):
        missing = get_missing_scope_claims(
            profile.get("scopes", ""),
            userinfo,
            profile.get("scope_expected_claims"),
        )
        if missing:
            logger.debug(
                "userinfo fallback triggered for realm=%s sub=%s missing=%s",
                realm, userinfo.get("sub"), missing,
            )
            userinfo = enrich_userinfo_from_endpoint(
                client,
                tokens.get("access_token"),
                userinfo,
                missing,
                realm=realm,
                sub=userinfo.get("sub"),
            )

    # ACR assertion: reject login if the ID token does not meet configured assurance requirements.
    required_acr = profile.get("required_acr")
    if required_acr:
        failed_acr = check_acr(userinfo, required_acr)
        if failed_acr:
            audit_event("device_login_acr_rejected",
                        realm=realm,
                        sub=userinfo.get("sub"),
                        acr=userinfo.get("acr"),
                        failed_requirements=failed_acr)
            abort(403, description="Insufficient authentication assurance level")

    # Determine refresh expiration
    now = int(time.time())
    absolute_session_lifetime_secs = tokens.get("refresh_expires_in")
    # 0 generally indicates "no expiry" (dubious) and None isn't helpful, so fall back to the configured value or default
    if not absolute_session_lifetime_secs:
        # default to 14 days if not configured
        absolute_session_lifetime_secs = current_app.config.get("MAX_REFRESH_TOKEN_LIFETIME", 14) * 86400
        absolute_expires_at = now + absolute_session_lifetime_secs
    else:
        absolute_expires_at = now + absolute_session_lifetime_secs

    metadata = {
        "allow_automatic_refresh":  flow.get("refresh", False),
        "offline_access_granted":   offline_granted,
        "access_token_expires_at":  tokens.get("expires_at"),
        "refresh_token_expires_at": absolute_expires_at
    }

    # Augment the session, if applicable
    userinfo, additional_tokens = augment_session(tokens, realm, userinfo, metadata)

    session_id = store.generate_session_id()
    session_key, session_data = store.create_session(
        session_id=session_id,
        session_type=SessionType.DEVICE,
        access_token=tokens.get("access_token"),
        id_token=tokens.get("id_token"),
        refresh_token=tokens.get("refresh_token"),
        scopes=scopes_granted,
        userinfo=userinfo,
        realm=realm,
        allowed_resources=flow.get("allowed_resources",[]),
        metadata=metadata,
        additional_tokens=additional_tokens,
        expires_at=absolute_expires_at,
        absolute_session_lifetime_secs = absolute_session_lifetime_secs
    )

    flow.update({"verified": True, "session_key": session_key, "nonce": None, "code_verifier": None})
    store.set_device_flow(device_code, flow, ttl=current_app.config.get("DEVICE_FLOW_TTL", DEVICE_FLOW_TTL))

    if metadata.get("augmentation_deferred", False):
        g.session_key = session_key
        userinfo, additional_tokens = augment_session(tokens, realm, userinfo, metadata)
        metadata.pop("augmentation_deferred", None)
        session_data.userinfo = userinfo
        session_data.additional_tokens = additional_tokens
        store.update_session(session_id, session_data)

    sub = userinfo.get("sub")
    user = userinfo.get("email")
    txn = extract_jwt_txn(tokens.get("access_token", ""))
    logger.info(f"Device login successful for user {user} ({sub}) with session id {session_id} on realm {realm}")
    audit_event("device_login",
                session_id=session_id,
                user=user,
                sub=sub,
                scopes=get_effective_scopes(session_data),
                allowed_resources=session_data.allowed_resources,
                realm=realm,
                offline_access=offline_granted,
                refresh_expires_at=datetime.fromtimestamp(session_data.absolute_expires_at, timezone.utc).isoformat(),
                **({"txn": txn} if txn else {}))

    return render_template_string(SUCCESS_HTML)


SUCCESS_HTML = \
"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Device Authorized</title>
    <style>
        body { font-family: system-ui, sans-serif; display: flex;
               justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; background: #f5f5f5; }
        .card { background: white; padding: 2rem; border-radius: 8px;
                text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #22c55e; margin: 0 0 0.5rem; }
    </style>
</head>
<body>
    <div class="card">
        <h1>Device Authorized</h1>
        <p>You may close this window and return to your device.</p>
    </div>
</body>
</html>"""
