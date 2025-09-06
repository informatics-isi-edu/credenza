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
from urllib.parse import urlencode, quote
from flask import Blueprint, request, redirect, current_app, make_response, abort, jsonify, g
from ..api.session.storage.session_store import TRANSIENT_DATA_TTL
from ..api.util import has_current_session, get_effective_scopes, generate_nonce, augment_session, get_cookie_domain, \
    revoke_tokens, safe_referrer, is_transient_request_error
from ..telemetry import audit_event

logger = logging.getLogger(__name__)

login_blueprint = Blueprint("login", __name__)

@login_blueprint.route("/login")
def login():

    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    store = current_app.config["SESSION_STORE"]
    realm = current_app.config["DEFAULT_REALM"]
    client = factory.get_client(realm)

    try:
        client = factory.get_client(realm)
    except Exception as e:
        abort(502, description=f"OIDC client init failed: {e}")

    referrer = safe_referrer(request.args.get('referrer')) or current_app.config.get("POST_LOGIN_REDIRECT", "/")
    logger.debug("Login referrer: %s", referrer)

    sid = has_current_session()
    if sid is not None:
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
    store.store_authn_request_ctx(state, authn_request_ctx, ttl=TRANSIENT_DATA_TTL)

    return redirect(auth_url)

@login_blueprint.route("/callback")
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
    try:
        client = factory.get_client(realm)
    except Exception as e:
        abort(502, description=f"OIDC client init failed: {e}")

    preserve_ctx = False
    try:
        now = int(time.time())
        if now - int(authn_request_ctx.get("created_at", 0)) > TRANSIENT_DATA_TTL:
            abort(400, description="State expired")

        code_verifier =authn_request_ctx.get("code_verifier")
        if current_app.config.get("ENABLE_PKCE", True) and not code_verifier:
            abort(400, "Missing PKCE verifier")

        try:
            redirect_uri = authn_request_ctx.get("redirect_uri")
            tokens = client.exchange_code_for_tokens(code, redirect_uri, code_verifier)
        except Exception as e:
            if is_transient_request_error(e):
                preserve_ctx = True
                # keep context briefly so user can retry
                age = now - int(authn_request_ctx.get("created_at", 0))
                remaining = max(0, TRANSIENT_DATA_TTL - age)
                if remaining == 0:
                    abort(400, description="State expired")
                store.store_authn_request_ctx(state, authn_request_ctx, ttl=min(60, remaining))
                abort(502, description=f"Token exchange failed (temporary): {e}")
            abort(400, description=f"Token exchange failed: {e}")  # non-transient -> delete in finally

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
            abort(400, description=f"Unable to validate id_token: {e}")

        # Augment the session, if applicable
        userinfo, additional_tokens = augment_session(tokens, realm, userinfo, metadata)

        sid = store.generate_session_id()
        session_key, session_data = store.create_session(
            session_id=sid,
            id_token=tokens.get("id_token"),
            access_token=tokens.get("access_token"),
            refresh_token=tokens.get("refresh_token"),
            scopes=scopes_granted,
            userinfo=userinfo,
            realm=realm,
            metadata=metadata,
            additional_tokens=additional_tokens
        )

        sub = userinfo.get("sub")
        user = userinfo.get("email")
        audit_event("login",
                    session_id=sid,
                    user=user,
                    sub=sub,
                    scopes=get_effective_scopes(session_data),
                    realm=realm)
        logger.info(f"Login successful for user {user} ({sub}) with session id {sid} on realm {realm}")

        if metadata.get("augmentation_deferred", False):
            g.session_key = session_key
            userinfo, additional_tokens = augment_session(tokens, realm, userinfo, metadata)
            metadata.pop("augmentation_deferred", None)
            session_data.userinfo = userinfo
            session_data.metadata = metadata
            session_data.additional_tokens = additional_tokens
            store.update_session(sid, session_data)

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
def logout():
    post_logout_redirect_uri = current_app.config.get("POST_LOGOUT_REDIRECT_URL", "/")
    sid = has_current_session()
    if sid is None:
        return redirect(post_logout_redirect_uri)

    store = current_app.config["SESSION_STORE"]
    session = store.get_session_data(sid)

    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    profile = current_app.config["OIDC_IDP_PROFILES"].get(realm, {})
    logout_url = profile.get("logout_url")
    logout_url_params = profile.get("logout_url_params")

    revoke_tokens(sid, session)
    store.delete_session(sid)

    audit_event("logout", session_id=sid, user=user, sub=sub, realm=realm)
    logger.info(f"Logout for user {user} ({sub}) with session id {sid} on realm {realm}.")

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
def preauth():
    do_redirect = request.args.get('do_redirect')
    referrer_arg = request.args.get('referrer')
    referer_header = request.environ.get('HTTP_REFERER')
    post_login_redirect = current_app.config.get("POST_LOGIN_REDIRECT", "/")
    referrer = safe_referrer(referrer_arg or referer_header or post_login_redirect) or "/"
    redirect_url = f"{current_app.config['BASE_URL']}/login?referrer={quote(referrer, safe='')}"

    if do_redirect:
        return redirect(redirect_url, code=303)

    return jsonify({"redirect_url": redirect_url})
