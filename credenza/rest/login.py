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
import logging
import time
import uuid
from secrets import token_urlsafe, token_hex
from urllib.parse import urlencode, quote
from flask import Blueprint, request, redirect, current_app, make_response, abort, jsonify, g
from .helpers import get_cookie_domain, perf_logged
from .consent import is_consent_needed
from ..telemetry import audit_event
from ..api.session.storage.session_store import TRANSIENT_DATA_TTL, SessionType
from ..api.common.crypto import generate_nonce
from ..api.common.util import (
    get_current_session,
    get_effective_scopes,
    augment_session,
    enrich_userinfo_from_endpoint,
    get_missing_scope_claims,
    extract_jwt_txn,
    check_acr,
    revoke_tokens,
    safe_referrer,
    is_transient_request_error
)

logger = logging.getLogger(__name__)

login_blueprint = Blueprint("login", __name__)

@login_blueprint.route("/login")
@perf_logged(warn_ms=1000)
def login():

    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    store = current_app.config["SESSION_STORE"]
    realm = current_app.config["DEFAULT_REALM"]

    try:
        client = factory.get_client(realm)
    except Exception as e:
        msg = "OIDC client init failed"
        logger.error(f"{msg}: {e}")
        abort(502, description=msg)

    referrer = safe_referrer(request.args.get('referrer')) or current_app.config.get("POST_LOGIN_REDIRECT", "/")
    logger.debug("Login referrer: %s", referrer)

    sid, session = get_current_session(dont_abort=True)
    if sid and session:
        return redirect(referrer)

    state = uuid.uuid4().hex
    nonce = generate_nonce()
    redirect_uri = f"{current_app.config['BASE_URL']}/callback"

    auth_url, auth_state, code_verifier = client.create_authorization_url(
        use_pkce=current_app.config.get("ENABLE_PKCE", True),
        is_device=False,
        state=state,
        nonce=nonce,
        redirect_uri=redirect_uri
    )

    authn_request_ctx = {
        "nonce": nonce,
        "code_verifier": code_verifier,
        "scope": client.scope,
        "realm": realm,
        "referrer": referrer,
        "redirect_uri": redirect_uri,
        "created_at": int(time.time()),
    }
    store.set_authn_request_ctx(state, authn_request_ctx, ttl=TRANSIENT_DATA_TTL)

    return redirect(auth_url)

@login_blueprint.route("/callback")
@perf_logged(warn_ms=1000)
def callback():
    err = request.args.get("error")
    if err:
        desc = request.args.get("error_description") or err
        abort(400, description=f"Authorization error: {desc}")

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state:
        abort(400, description="Callback is missing code or state")

    store = current_app.config["SESSION_STORE"]
    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    metadata = {}

    authn_request_ctx = store.get_authn_request_ctx(state)
    if not authn_request_ctx:
        abort(400, description=f"Missing or expired request context for state: {state}")

    realm = authn_request_ctx.get("realm")
    is_oauth_flow = bool(authn_request_ctx.get("oauth_client_id"))
    try:
        client = factory.get_client(realm)
    except Exception as e:
        msg = "OIDC client init failed"
        logger.error(f"{msg}: {e}")
        abort(502, description=msg)

    preserve_ctx = False
    try:
        now = int(time.time())
        if now - int(authn_request_ctx.get("created_at", 0)) > TRANSIENT_DATA_TTL:
            abort(400, description="State expired")

        code_verifier = authn_request_ctx.get("code_verifier")
        if current_app.config.get("ENABLE_PKCE", True) and not code_verifier:
            abort(400, "Missing PKCE verifier")

        try:
            redirect_uri = authn_request_ctx.get("redirect_uri")
            tokens = client.exchange_code_for_tokens(code, redirect_uri, code_verifier)
        except Exception as e:
            msg = "Token exchange failed"
            logger.error(f"{msg}: {e}")
            if is_transient_request_error(e):
                preserve_ctx = True
                # keep context briefly so user can retry
                age = now - int(authn_request_ctx.get("created_at", 0))
                remaining = max(0, TRANSIENT_DATA_TTL - age)
                if remaining == 0:
                    abort(400, description="State expired")
                store.set_authn_request_ctx(state, authn_request_ctx, ttl=min(60, remaining))
                abort(502, description=f"{msg} (temporary)")
            abort(400, description=msg)  # non-transient -> delete in finally

        scopes_granted = tokens.get('scope', authn_request_ctx.get("scope"))

        # for now, do not support refresh tokens in non-device logins, even if the IDP (e.g. Keycloak) returns them
        if "refresh_token" in tokens:
            tokens["refresh_token"] = None

        # Validate nonce and token claims
        nonce = authn_request_ctx.get("nonce")
        if not nonce:
            abort(400, description="Missing or expired nonce")
        try:
            userinfo = client.validate_id_token(tokens["id_token"], nonce)
        except Exception as e:
            msg = "Unable to validate id_token"
            logger.error(f"{msg}: {e}")
            abort(400, description=msg)

        # Fallback to IDP userinfo endpoint if the ID token is missing key claims
        # for the scopes that were requested. Fires automatically; opt out per
        # realm with skip_userinfo_fallback: true in the IDP profile. Never aborts
        # -- the session is created in degraded form if the endpoint also fails.
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
                audit_event("login_acr_rejected",
                            realm=realm,
                            sub=userinfo.get("sub"),
                            acr=userinfo.get("acr"),
                            failed_requirements=failed_acr)
                abort(403, description="Insufficient authentication assurance level")

        # Augment the session, if applicable
        userinfo, additional_tokens = augment_session(tokens, realm, userinfo, metadata)

        sid = store.generate_session_id()
        session_key, session_data = store.create_session(
            session_id=sid,
            session_type=SessionType.USER,
            id_token=tokens.get("id_token"),
            access_token=tokens.get("access_token"),
            refresh_token=tokens.get("refresh_token"),
            scopes=scopes_granted,
            userinfo=userinfo,
            realm=realm,
            metadata=metadata,
            additional_tokens=additional_tokens,
            allowed_resources=authn_request_ctx.get("oauth_resources") if is_oauth_flow else None,
            session_ttl=authn_request_ctx.get("oauth_session_ttl") if is_oauth_flow else None,
        )

        sub = userinfo.get("sub")
        user = userinfo.get("email")
        txn = extract_jwt_txn(tokens.get("access_token", ""))
        logger.info(f"Login successful for user {user} ({sub}) with session id {sid} on realm {realm}")
        audit_event("login",
                    session_id=sid,
                    user=user,
                    sub=sub,
                    scopes=get_effective_scopes(session_data),
                    realm=realm,
                    **({"txn": txn} if txn else {}))

        if metadata.get("augmentation_deferred", False):
            g.session_key = session_key
            userinfo, additional_tokens = augment_session(tokens, realm, userinfo, metadata)
            metadata.pop("augmentation_deferred", None)
            session_data.userinfo = userinfo
            session_data.additional_tokens = additional_tokens
            store.update_session(sid, session_data)

        if is_oauth_flow:
            # Consent check (ADR-0002): show consent page if client requires it and no
            # valid consent record exists for this principal + client/resource combination.
            client_id = authn_request_ctx["oauth_client_id"]
            registry = current_app.config.get("CLIENT_REGISTRY")
            client_rec = registry.get(client_id) if registry else None
            if client_rec and client_rec.require_consent:
                iss = userinfo.get("iss", "")
                principal = f"{iss}/{sub}" if iss else sub
                resources = authn_request_ctx.get("oauth_resources") or []
                if is_consent_needed(store, registry, principal, client_id, resources):
                    pending_key = token_hex(16)
                    store.set_pending_consent(pending_key, {
                        "session_id":            sid,
                        "sub":                   sub,
                        "principal":             principal,
                        "client_id":             client_id,
                        "redirect_uri":          authn_request_ctx["oauth_redirect_uri"],
                        "oauth_state":           authn_request_ctx.get("oauth_state", ""),
                        "code_challenge":        authn_request_ctx.get("oauth_code_challenge"),
                        "code_challenge_method": authn_request_ctx.get("oauth_code_challenge_method"),
                        "scope":                 authn_request_ctx.get("oauth_scope", ""),
                        "resources":             resources,
                        "realm":                 realm,
                    })
                    return redirect(
                        f"{current_app.config['BASE_URL']}/authorize/consent?pending={pending_key}"
                    )

            # OAuth Authorization Code flow: generate code and redirect back to client
            auth_code = token_urlsafe(32)
            code_payload = {
                "session_id":            sid,
                "client_id":             authn_request_ctx["oauth_client_id"],
                "redirect_uri":          authn_request_ctx["oauth_redirect_uri"],
                "code_challenge":        authn_request_ctx.get("oauth_code_challenge"),
                "code_challenge_method": authn_request_ctx.get("oauth_code_challenge_method"),
                "scope":                 authn_request_ctx.get("oauth_scope", ""),
                "resources":             authn_request_ctx.get("oauth_resources", []),
                "realm":                 realm,
                "issued_at":             int(time.time()),
            }
            store.set_authorization_code(auth_code, code_payload, ttl=300)
            logger.info(
                f"OAuth authorization code issued for user {user} ({sub}), "
                f"client={authn_request_ctx['oauth_client_id']}, session={sid}")
            audit_event("authorization_code_issued",
                        session_id=sid,
                        client_id=authn_request_ctx["oauth_client_id"],
                        user=user,
                        sub=sub,
                        realm=realm)
            client_state = authn_request_ctx.get("oauth_state", "")
            params = {"code": auth_code}
            if client_state:
                params["state"] = client_state
            return redirect(f"{authn_request_ctx['oauth_redirect_uri']}?{urlencode(params)}")
        else:
            referrer = authn_request_ctx.get("referrer", current_app.config.get("POST_LOGIN_REDIRECT", "/"))
            logger.debug(f"Callback referrer: {referrer}")
            response = redirect(referrer)
            response.set_cookie(current_app.config["COOKIE_NAME"],
                                session_key,
                                domain=get_cookie_domain(),
                                httponly=True,
                                secure=True,
                                samesite="Lax")
            return response

    finally:
        if not preserve_ctx:
            try:
                store.delete_authn_request_ctx(state)
            except Exception:
                logger.exception(f"Failed to delete authn_request_ctx for state {state}")


@login_blueprint.route("/logout", methods=["GET"])
@perf_logged(warn_ms=1000)
def logout():
    post_logout_redirect_uri = current_app.config.get("POST_LOGOUT_REDIRECT_URL", "/")
    sid, session = get_current_session(dont_abort=True)
    if sid is None or session is None:
        return redirect(post_logout_redirect_uri)

    store = current_app.config["SESSION_STORE"]
    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    profile = current_app.config["OIDC_IDP_PROFILES"].get(realm, {})
    factory = current_app.config["OIDC_CLIENT_FACTORY"]

    try:
        client = factory.get_client(realm)
    except Exception as e:
        msg = "OIDC client init failed"
        logger.error(f"{msg}: {e}")
        abort(502, description=msg)

    logout_url = client.logout_url
    logout_url_params = profile.get("logout_url_params")

    revoke_tokens(sid, session)
    store.delete_session(sid)

    logger.info(f"Logout for user {user} ({sub}) with session id {sid} on realm {realm}.")
    audit_event("logout", session_id=sid, user=user, sub=sub, realm=realm)

    if logout_url:
        if logout_url_params:
            query = logout_url_params
        else:
            query = {
                "id_token_hint": session.id_token,
                "post_logout_redirect_uri": post_logout_redirect_uri,
            }
        redirect_uri = f"{logout_url}?{urlencode(query)}"
    else:
        redirect_uri = post_logout_redirect_uri

    if current_app.config.get("ENABLE_LEGACY_API", False):
        resp = make_response({"logout_url": redirect_uri})
    else:
        resp = make_response(redirect(redirect_uri))

    resp.set_cookie(
        current_app.config["COOKIE_NAME"], "",
        expires=0,
        domain=get_cookie_domain(),
        secure=True, httponly=True, samesite="Lax"
    )
    return resp

# This is a webauthn2 legacy compatibility endpoint
@login_blueprint.route("/preauth")
@perf_logged(warn_ms=1000)
def preauth():
    if not current_app.config.get("ENABLE_LEGACY_API", False):
        abort(404)

    do_redirect = request.args.get('do_redirect')
    referrer_arg = request.args.get('referrer')
    referer_header = request.environ.get('HTTP_REFERER')
    post_login_redirect = current_app.config.get("POST_LOGIN_REDIRECT", "/")
    referrer = safe_referrer(referrer_arg or referer_header or post_login_redirect) or "/"
    redirect_url = f"{current_app.config['BASE_URL']}/login?referrer={quote(referrer, safe='')}"

    if do_redirect:
        return redirect(redirect_url, code=303)

    return jsonify({"redirect_url": redirect_url})
