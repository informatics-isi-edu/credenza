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
from secrets import token_urlsafe
from urllib.parse import urlencode, urlsplit
from flask import Blueprint, request, redirect, abort, current_app
from .helpers import perf_logged, get_request_id
from ..telemetry import audit_event
from ..api.session.storage.session_store import TRANSIENT_DATA_TTL
from ..api.common.crypto import generate_nonce
from ..api.common.util import normalize_str_list

logger = logging.getLogger(__name__)

authorize_blueprint = Blueprint("authorize", __name__)

# Loopback hosts eligible for the RFC 8252 sec. 7.3 port-flexible match.
# The IP literals are preferred by the RFC; "localhost" is NOT RECOMMENDED but
# accepted here because common native clients (e.g. Claude Code) use it.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


def _is_loopback_http(parts):
    """True if a urlsplit() result is an http loopback redirect URI."""
    return parts.scheme == "http" and parts.hostname in _LOOPBACK_HOSTS


def redirect_uri_allowed(requested, allowed_uris):
    """
    Match a requested redirect_uri against a client's registered list.

    Exact string match per RFC 6749 sec. 3.1.2.3, plus the RFC 8252 sec. 7.3
    loopback exception: for http loopback redirects the authorization server
    MUST allow any port, so a requested loopback URI matches a registered
    loopback URI with the same scheme, host, and path regardless of port.

    The exception relaxes the port only -- a loopback redirect still must be
    registered with a matching scheme/host/path, preserving default-deny. Host
    tokens are compared as-is, so a registered "localhost" entry does not match
    a requested "127.0.0.1" (and vice versa). Gated by LOOPBACK_REDIRECT_ANY_PORT.
    """
    allowed = allowed_uris or []
    if requested in allowed:
        return True
    if not current_app.config.get("LOOPBACK_REDIRECT_ANY_PORT", True):
        return False
    req = urlsplit(requested)
    if not _is_loopback_http(req):
        return False
    for candidate in allowed:
        cand = urlsplit(candidate)
        if _is_loopback_http(cand) and cand.hostname == req.hostname and cand.path == req.path:
            return True
    return False


@authorize_blueprint.route("/authorize", methods=["GET"])
@perf_logged(warn_ms=1000)
def authorize():
    """
    GET /authorize -- OAuth 2.1 Authorization Code + PKCE endpoint.

    Error handling per RFC 6749 sec. 4.1.2.1:
      - Missing/invalid client_id or redirect_uri: 400/401 (no redirect -- redirect_uri unverified).
      - All other param errors: redirect to redirect_uri with error/error_description params.
    """
    store = current_app.config["SESSION_STORE"]
    client_registry = current_app.config["CLIENT_REGISTRY"]
    factory = current_app.config["OIDC_CLIENT_FACTORY"]
    realm = current_app.config["DEFAULT_REALM"]

    # 1: Validate client_id and redirect_uri (errors: 400/401, NOT redirects)
    client_id = (request.args.get("client_id") or "").strip()
    if not client_id:
        audit_event("authorize_missing_client_id", request_id=get_request_id())
        abort(400, description="missing client_id")

    client_rec = client_registry.get(client_id)
    if client_rec is None or not client_rec.enabled:
        audit_event("authorize_unknown_client",
                    client_id=client_id,
                    request_id=get_request_id())
        abort(401, description="unknown or disabled client")

    redirect_uri = (request.args.get("redirect_uri") or "").strip()
    if not redirect_uri:
        abort(400, description="missing redirect_uri")
    if not redirect_uri_allowed(redirect_uri, client_rec.allowed_redirect_uris):
        audit_event("authorize_invalid_redirect_uri",
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    request_id=get_request_id())
        abort(400, description="redirect_uri not registered for this client")

    # 2: All further errors redirect to redirect_uri with error params
    state = (request.args.get("state") or "").strip()

    def _redirect_error(error: str, description=None):
        params = {"error": error}
        if state:
            params["state"] = state
        if description:
            params["error_description"] = description
        return redirect(f"{redirect_uri}?{urlencode(params)}", 302)

    # authorization_code grant must be allowed for this client
    if "authorization_code" not in (client_rec.allowed_grant_types or []):
        audit_event("authorize_grant_not_allowed",
                    client_id=client_id,
                    request_id=get_request_id())
        return _redirect_error("unauthorized_client")

    # response_type must be "code"
    response_type = (request.args.get("response_type") or "").strip()
    if response_type != "code":
        return _redirect_error("unsupported_response_type")

    # PKCE validation -- S256 only; required for public clients
    code_challenge = (request.args.get("code_challenge") or "").strip()
    code_challenge_method = (request.args.get("code_challenge_method") or "").strip()
    if client_rec.public:
        if not code_challenge:
            return _redirect_error("invalid_request",
                                   "code_challenge required for public clients")
        if code_challenge_method != "S256":
            return _redirect_error("invalid_request",
                                   "code_challenge_method must be S256")
    elif code_challenge and code_challenge_method != "S256":
        # Confidential client optionally uses PKCE -- must also be S256
        return _redirect_error("invalid_request",
                               "code_challenge_method must be S256")

    # Scope validation
    req_scope = (request.args.get("scope") or "").strip()
    requested_scopes = sorted(dict.fromkeys(s for s in req_scope.split() if s)) if req_scope else []
    allowed_scopes = list(client_rec.allowed_scopes or [])
    if allowed_scopes and requested_scopes:
        disallowed = set(requested_scopes) - set(allowed_scopes)
        if disallowed:
            return _redirect_error("invalid_scope",
                                   f"scopes not permitted: {sorted(disallowed)}")
    if not requested_scopes:
        requested_scopes = list(client_rec.default_scopes or [])

    # Resource validation
    requested_resources = normalize_str_list(request.args.getlist("resource"))
    allowed_resources = list(client_rec.allowed_resources or [])
    if requested_resources:
        disallowed_res = set(requested_resources) - set(allowed_resources)
        if disallowed_res:
            return _redirect_error("invalid_target",
                                   f"resources not permitted: {sorted(disallowed_res)}")
    if not requested_resources:
        requested_resources = list(client_rec.default_resources or [])

    # 3: Initiate upstream OIDC login via existing machinery
    try:
        oidc_client = factory.get_client(realm)
    except Exception as e:
        msg = "OIDC client init failed"
        logger.error(f"{msg}: {e}")
        abort(502, description=msg)

    oidc_state = token_urlsafe(16)
    nonce = generate_nonce()
    callback_uri = f"{current_app.config['BASE_URL']}/callback"

    # oidc_client.scope is the IDP-plane scope from the profile (e.g. Globus URN scopes).
    # It is independent of oauth_scope (the client-requested scope stored below).
    # The IDP profile must be configured as a superset of what any registered client may request.
    auth_url, _auth_state, code_verifier = oidc_client.create_authorization_url(
        use_pkce=current_app.config.get("ENABLE_PKCE", True),
        state=oidc_state,
        nonce=nonce,
        redirect_uri=callback_uri,
    )

    authn_request_ctx = {
        "nonce":          nonce,
        "code_verifier":  code_verifier,
        "scope":          oidc_client.scope,
        "realm":          realm,
        "referrer":       None,
        "redirect_uri":   callback_uri,
        "created_at":     int(time.time()),
        # OAuth code-flow metadata -- presence of oauth_client_id signals OAuth path in /callback
        "oauth_client_id":             client_id,
        "oauth_redirect_uri":          redirect_uri,
        "oauth_state":                 state,
        "oauth_scope":                 " ".join(requested_scopes),
        "oauth_resources":             requested_resources,
        "oauth_code_challenge":        code_challenge or None,
        "oauth_code_challenge_method": code_challenge_method or None,
        "oauth_session_ttl":           client_rec.max_session_ttl_seconds,
    }
    store.set_authn_request_ctx(oidc_state, authn_request_ctx, ttl=TRANSIENT_DATA_TTL)

    audit_event(
        "authorize_request",
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=authn_request_ctx["oauth_scope"],
        resources=requested_resources,
        request_id=get_request_id(),
    )

    return redirect(auth_url)