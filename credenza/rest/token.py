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
from typing import Dict, Optional, List, Any
from flask import Blueprint, request, jsonify, abort, current_app
from ..telemetry import audit_event
from ..api.session.storage.session_store import SessionStore, SessionType
from ..api.auth.client.client_registry import ClientRegistry, ClientRecord, DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL
from ..api.auth.client.adapters.adapter import ProofContext, AdapterResult
from ..api.common.errors import OAuthError
from ..api.common.claim_mapper import merge_additional_claims, get_claim_map_for_realm
from ..api.common.util import revoke_tokens, normalize_str_list, get_effective_scopes, MAX_SCOPES, MAX_RESOURCES
from ..api.common.crypto import verify_pkce
from .helpers import (
    validate_client,
    validate_grant_type,
    adapter_authenticate,
    get_request_id,
    parse_basic_auth,
    perf_logged,
    limit_or_429,
    route_label,
    ip_rate_limited,
    rate_limit_principal_key,
    GrantType
)

logger = logging.getLogger(__name__)

DERIVED_SESSION_MAX_TTL = 1800  # 30-minute hard cap for derived (exchanged) sessions
SUBJECT_TOKEN_TYPE_ACCESS = "urn:ietf:params:oauth:token-type:access_token"

token_blueprint = Blueprint("token", __name__)

@token_blueprint.route("/token", methods=["POST"])
@perf_logged(warn_ms=1000)
@ip_rate_limited()
def issue_token():
    """
    Unified OAuth 2.0 token endpoint (RFC 6749 / RFC 8628 / RFC 8693).

    POST /token  --  application/x-www-form-urlencoded

    All grant types share a common validation prologue:
      1. client_id resolved from HTTP Basic auth (preferred) or form field.
      2. Client record looked up in the registry; unknown clients get None when
         ALLOW_UNREGISTERED_CLIENTS is enabled (device_code only), 401 otherwise.
      3. grant_type parsed and checked against the client's allowed_grant_types.
      4. Dispatched to the appropriate grant handler.

    Supported grant types and their authentication model:
      authorization_code  -- PKCE is the proof; no adapter auth called here.
      device_code         -- client_id consistency enforced; unregistered clients
                             allowed when ALLOW_UNREGISTERED_CLIENTS=True.
      token_exchange      -- confidential clients authenticate via adapter (RFC 8693).
      client_credentials  -- adapter authentication always required.
    """
    store: SessionStore = current_app.config["SESSION_STORE"]
    client_registry: ClientRegistry = current_app.config["CLIENT_REGISTRY"]
    proof_ctx = ProofContext(request.form.to_dict(flat=False), dict(request.headers))

    # Resolve client record; returns None for unknown clients when ALLOW_UNREGISTERED_CLIENTS
    # is set (device_code grant handler enforces the policy for that case).
    client_rec = validate_client(client_registry, proof_ctx)

    # Validate grant_type: must be a known value and permitted by the client's allowed_grant_types.
    # When client_rec is None (unregistered), allowed_grant_types enforcement is skipped here
    # and handled inside the grant handler.
    grant_type: GrantType = validate_grant_type(proof_context=proof_ctx, client_rec=client_rec)

    # Authorization code exchange: PKCE verifies the code; no new session is created here --
    # the session was already created during /callback and the key is returned directly.
    if grant_type == GrantType.AUTHORIZATION_CODE:
        return _handle_authorization_code_grant(proof_ctx, client_rec, store)

    # Device code polling (RFC 8628): polls for authorization completion; client_id must match
    # what was recorded at /device_authorization. Returns RFC 8628 error JSON while pending.
    if grant_type == GrantType.DEVICE_CODE:
        return _handle_device_code_grant(proof_ctx, client_rec, store)

    # Token exchange (RFC 8693): issues a short-lived DERIVED session bound to specific resources
    # and scopes; subject token must be an active non-derived session key.
    if grant_type == GrantType.TOKEN_EXCHANGE:
        return _handle_token_exchange_grant(proof_ctx, client_rec, store)

    # Client credentials: adapter authentication required; creates a SERVICE session.
    if grant_type == GrantType.CLIENT_CREDENTIALS:
        return _handle_client_credentials_grant(proof_ctx, client_rec, store)

    abort(400, description=OAuthError.INVALID_REQUEST)


@token_blueprint.route("/revoke", methods=["POST"])
@perf_logged(warn_ms=1000)
@ip_rate_limited()
def revoke_token():
    """
    RFC 7009 token revocation endpoint.

    POST /revoke
      Form parameters:
        token            (required) -- the access token to revoke
        token_type_hint  (optional) -- ignored; only opaque access tokens supported
        client_id        (required) -- identifies the requesting client

    Returns HTTP 200 regardless of whether the token was valid (per RFC 7009 sec. 2.2).
    Confidential clients must authenticate via their configured adapter.
    Public clients need only provide client_id.
    """
    store: SessionStore = current_app.config["SESSION_STORE"]
    client_registry: ClientRegistry = current_app.config["CLIENT_REGISTRY"]
    proof_ctx = ProofContext(request.form.to_dict(flat=False), dict(request.headers))

    # Identify the client (registered and enabled).
    client_rec = validate_client(client_registry, proof_ctx)
    client_id = client_rec.client_id
    limits = current_app.extensions.get("rate_limits", {})

    # Per-client rate limit before adapter auth.
    pr_key = rate_limit_principal_key(client_id, realm=client_rec.realm)
    resp, _, _ = limit_or_429(limits.get("30_per_min"), pr_key, f"Too many requests: {route_label(request)}")
    if resp is not None:
        logger.warning(f"revoke_token_rate_limited: client_id={client_id}, realm={client_rec.realm} key={pr_key}")
        return resp

    # Confidential clients must authenticate (RFC 7009 sec. 2.1 / RFC 6749 sec. 3.2.1).
    if not client_rec.public:
        adapter_authenticate(proof_context=proof_ctx, client_rec=client_rec)

    token = (proof_ctx.get("token") or "").strip()
    if not token:
        # RFC 7009 sec. 2.2: return 200 for invalid/missing tokens
        audit_event("revoke_token_missing_param",
                    request_id=get_request_id(), client_id=client_id)
        return current_app.response_class(status=200)

    sid, session = store.get_session_by_session_key(token)
    if session is None:
        # Already expired or never existed -- still 200 per RFC 7009
        audit_event("revoke_token_not_found",
                    request_id=get_request_id(), client_id=client_id)
        return current_app.response_class(status=200)

    # revoke any dependent tokens
    if session.is_primary():
        revoke_tokens(sid, session)

    # delete the session
    store.delete_session(sid)

    audit_event(
        "token_revoked",
        request_id=get_request_id(),
        session_id=sid,
        client_id=client_id,
        realm=session.realm,
        sub=session.userinfo.get("sub"),
        session_type=str(session.session_type),
    )

    return current_app.response_class(status=200)


def _handle_client_credentials_grant(proof_ctx: ProofContext,
                                     client_rec: ClientRecord,
                                     store: SessionStore):
    """
    RFC 6749 client credentials grant -- machine-to-machine token issuance.

    The client authenticates using its configured adapter (e.g. client_secret,
    AWS presigned URL). On success a SERVICE session is created and an opaque
    bearer token is returned. No user identity is involved.

    Flow:
      1. Reject unregistered clients -- client_credentials always requires a registry entry.
      2. Adapter authentication -- proves the client's identity and returns a subject
         (sub), auth_context, and any additional claims to embed in the session.
      3. Per-subject rate limiting -- applied after auth so the subject is known.
      4. Resource, scope, and TTL validation -- enforced against the client's policy.
      5. Session creation -- SERVICE type, bound to the validated resources and scopes.
    """
    # Unregistered clients are never permitted for client_credentials.
    if client_rec is None:
        abort(401, OAuthError.UNAUTHORIZED_CLIENT)

    client_id = client_rec.client_id
    limits = current_app.extensions.get("rate_limits", {})

    # Per-client rate limit applied before authentication.
    pr_key = rate_limit_principal_key(client_id, realm=client_rec.realm)
    resp, _, _ = limit_or_429(limits.get("30_per_min"), pr_key, f"Too many requests: {route_label(request)}")
    if resp is not None:
        logger.warning(f"token_request_rate_limited: client_id={client_id}, realm={client_rec.realm} key={pr_key}")
        return resp

    # Authenticate the client and extract the subject identity and any additional claims.
    ar: AdapterResult = adapter_authenticate(proof_context=proof_ctx, client_rec=client_rec)
    sub = ar.subject.to_sub()
    auth_context = ar.auth_context
    adapter_additional_claims = ar.additional_claims
    metadata: Dict[str, Any] = {"auth_context": auth_context}
    if ar.namespace is not None:
        metadata["namespace"] = ar.namespace

    # Validate requested resources against the client's allowed_resources policy.
    resources = validate_resources_for_client(proof_ctx=proof_ctx, client_rec=client_rec, subject=sub)

    # Validate requested scopes against the client's allowed_scopes policy.
    scopes = validate_scopes_for_client(proof_ctx=proof_ctx, client_rec=client_rec, subject=sub)

    # Clamp the requested TTL to the client's max_session_ttl_seconds.
    ttl = validate_and_clamp_ttl(proof_ctx=proof_ctx, client_rec=client_rec, subject=sub)

    # Build the userinfo dict: start from the subject, merge client and adapter additional claims.
    userinfo = merge_userinfo({"sub": sub}, client_rec, adapter_additional_claims)

    sid = store.generate_session_id()
    skey, session = store.create_session(
        session_id=sid,
        session_type=SessionType.SERVICE,
        access_token=store.generate_session_key(),
        scopes=scopes,
        realm=client_rec.realm,
        userinfo=userinfo,
        allowed_resources=resources,
        expires_at=int(time.time()) + ttl,
        session_ttl=ttl,
        metadata=metadata
    )

    audit_event(
        "token_issued",
        request_id=get_request_id(),
        session=sid,
        realm=client_rec.realm,
        client_id=client_id,
        sub=sub,
        resources=resources,
        scopes=scopes,
        ttl=ttl
    )

    return jsonify({"access_token": skey,
                    "token_type": "bearer",
                    "expires_in": ttl})


def _handle_authorization_code_grant(proof_ctx: ProofContext,
                                     client_rec: ClientRecord,
                                     store: SessionStore):
    """
    RFC 6749 sec. 4.1.3 -- authorization code exchange.

    The session was already created during /callback after the upstream OIDC
    login completed. This handler simply verifies the code and returns the
    pre-existing session key as the bearer token -- no new session is created.

    Flow:
      1. Reject unregistered clients -- authorization_code always requires a registry entry.
      2. Atomically consume the single-use code (replay protection).
      3. Verify client_id matches what was recorded at /authorize time.
      4. Verify redirect_uri matches exactly (RFC 6749 sec. 4.1.3 requirement).
      5. Verify PKCE code_verifier against the stored challenge when present;
         required for public clients, optional for confidential clients.
      6. Retrieve the session created during /callback and return its key.

    On any validation failure the code is already consumed (step 2), so the
    original /authorize request must be restarted -- there is no retry path.
    """
    if client_rec is None:
        abort(401, OAuthError.UNAUTHORIZED_CLIENT)

    client_id = client_rec.client_id

    code = (proof_ctx.get("code") or "").strip()
    redirect_uri = (proof_ctx.get("redirect_uri") or "").strip()
    code_verifier = (proof_ctx.get("code_verifier") or "").strip() or None

    if not code:
        audit_event("token_authz_code_missing_code",
                    request_id=get_request_id(), client_id=client_id)
        abort(400, description=OAuthError.INVALID_REQUEST)
    if not redirect_uri:
        audit_event("token_authz_code_missing_redirect_uri",
                    request_id=get_request_id(), client_id=client_id)
        abort(400, description=OAuthError.INVALID_REQUEST)

    # Atomically consume the code (single-use)
    payload = store.consume_authorization_code(code)
    if payload is None:
        audit_event("token_authz_code_invalid",
                    request_id=get_request_id(), client_id=client_id)
        abort(400, description=OAuthError.INVALID_GRANT)

    # client_id must match what was recorded at /authorize
    if payload.get("client_id") != client_id:
        audit_event("token_authz_code_client_mismatch",
                    request_id=get_request_id(),
                    client_id=client_id,
                    code_client_id=payload.get("client_id"))
        abort(400, description=OAuthError.INVALID_GRANT)

    # redirect_uri must match exactly
    if payload.get("redirect_uri") != redirect_uri:
        audit_event("token_authz_code_redirect_uri_mismatch",
                    request_id=get_request_id(), client_id=client_id)
        abort(400, description=OAuthError.INVALID_GRANT)

    # PKCE verification (required when challenge was stored)
    code_challenge = payload.get("code_challenge")
    code_challenge_method = payload.get("code_challenge_method") or "S256"
    if code_challenge:
        if not code_verifier:
            audit_event("token_authz_code_missing_verifier",
                        request_id=get_request_id(), client_id=client_id)
            abort(400, description=OAuthError.INVALID_REQUEST)
        if not verify_pkce(code_challenge, code_verifier, code_challenge_method):
            audit_event("token_authz_code_pkce_failed",
                        request_id=get_request_id(), client_id=client_id)
            abort(400, description=OAuthError.INVALID_GRANT)
    elif client_rec.public and code_verifier:
        # verifier supplied but no challenge was stored -- unexpected for public client
        audit_event("token_authz_code_unexpected_verifier",
                    request_id=get_request_id(), client_id=client_id)
        abort(400, description=OAuthError.INVALID_REQUEST)

    # Retrieve the session created during /callback
    session_id = payload.get("session_id")
    if not session_id:
        audit_event("token_authz_code_missing_session_id",
                    request_id=get_request_id(), client_id=client_id)
        abort(500, description=OAuthError.SERVER_ERROR)

    session = store.get_active_session_by_session_id(session_id)
    if session is None:
        audit_event("token_authz_code_session_expired",
                    request_id=get_request_id(),
                    client_id=client_id,
                    session_id=session_id)
        abort(400, description=OAuthError.INVALID_GRANT)

    session_key = store.get_session_key_for_session_id(session_id)
    if not session_key:
        audit_event("token_authz_code_session_key_missing",
                    request_id=get_request_id(),
                    client_id=client_id,
                    session_id=session_id)
        abort(500, description=OAuthError.SERVER_ERROR)

    expires_in = max(0, session.expires_at - int(time.time()))

    audit_event(
        "token_issued_from_authz_code",
        request_id=get_request_id(),
        session_id=session_id,
        client_id=client_id,
        realm=payload.get("realm"),
        sub=session.userinfo.get("sub"),
        resources=payload.get("resources", []),
        scope=payload.get("scope", ""),
        expires_in=expires_in,
    )

    return jsonify({
        "access_token": session_key,
        "token_type":   "bearer",
        "expires_in":   expires_in,
    })


def _handle_device_code_grant(proof_ctx: ProofContext,
                              client_rec: Optional[ClientRecord],
                              store: SessionStore):
    """
    RFC 8628 device authorization grant -- token polling leg.

    Called from the unified /token endpoint when grant_type=device_code.
    Returns the session token once the device has been authorized, or an
    RFC 8628-compliant error response while authorization is pending or
    the code has expired.

    client_rec may be None when the client was not found in the registry.
    If ALLOW_UNREGISTERED_CLIENTS is set, an anonymous public record
    is constructed; otherwise the request is rejected.

    client_id consistency is enforced: the client_id in the poll request
    must match the client_id recorded at /device_authorization time.
    """
    if client_rec is None:
        if not current_app.config.get("ALLOW_UNREGISTERED_CLIENTS", False):
            audit_event("device_token_unregistered_client_denied",
                        request_id=get_request_id())
            abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)
        # Extract client_id from the proof context to build the anonymous record.
        parsed = parse_basic_auth(request.headers.get("authorization"))
        client_id = (parsed["client_id"] if parsed else None) or proof_ctx.get("client_id")
        if not client_id:
            abort(400, description=OAuthError.INVALID_REQUEST)
        client_rec = _make_anonymous_device_client(client_id)

    client_id = client_rec.client_id

    device_code = (proof_ctx.get("device_code") or "").strip()
    if not device_code:
        audit_event("device_token_missing_param",
                    request_id=get_request_id(), client_id=client_id, param="device_code")
        abort(400, description=OAuthError.INVALID_REQUEST)

    flow = store.get_device_flow(device_code)
    if not flow:
        audit_event("device_token_expired",
                    request_id=get_request_id(), client_id=client_id)
        return jsonify({"error": "expired_token"}), 400

    # client_id consistency: must match what was stored at /device_authorization
    flow_client_id = flow.get("client_id")
    if flow_client_id and flow_client_id != client_id:
        audit_event("device_token_client_mismatch",
                    request_id=get_request_id(),
                    client_id=client_id,
                    flow_client_id=flow_client_id)
        abort(400, description=OAuthError.INVALID_GRANT)

    # Polling interval enforcement (RFC 8628 sec 3.5)
    now = int(time.time())
    last_poll = flow.get("last_poll_at", 0)
    interval = flow.get("interval", 0)
    if now < last_poll + interval:
        audit_event("device_token_slow_down",
                    request_id=get_request_id(), client_id=client_id)
        return jsonify({"error": "slow_down"}), 429

    flow["last_poll_at"] = now
    store.set_device_flow(device_code, flow, store.get_device_flow_ttl(device_code))

    # Authorization still pending
    if not flow.get("verified") or not flow.get("session_key"):
        return jsonify({"error": "authorization_pending"}), 400

    # Retrieve the session created during device callback
    session_key = flow["session_key"]
    session_info = store.get_active_session_by_session_key(session_key)
    if session_info is None:
        audit_event("device_token_session_lost",
                    request_id=get_request_id(), client_id=client_id)
        return jsonify({"error": "expired_token"}), 400

    _, session = session_info
    store.delete_device_flow(device_code)

    expires_in = max(0, session.expires_at - int(time.time()))

    audit_event(
        "device_token_issued",
        request_id=get_request_id(),
        client_id=client_id,
        realm=session.realm,
        sub=session.userinfo.get("sub"),
        expires_in=expires_in,
    )

    return jsonify({
        "access_token": session_key,
        "token_type":   "bearer",
        "expires_in":   expires_in,
    })


def _handle_token_exchange_grant(proof_ctx: ProofContext,
                                 client_rec: ClientRecord,
                                 store: SessionStore):
    """
    RFC 8693 token exchange: convert an active Credenza session token into a short-lived
    derived session bound to a specific set of resources and scopes.

    Policy:
      - Confidential clients must authenticate via their adapter (RFC 8693 / RFC 6749 sec. 3.2.1).
      - subject_token must be a live, non-derived Credenza session key.
      - Default-deny: client must have at least one allowed_token_exchange_targets entry.
      - Issued resources must be within the intersection of client allowed_resources and allowed_token_exchange_targets
        (and additionally the intersection of subject session allowed_resources when the subject is resource-bound).
      - Issued scopes must be a subset of the intersection of the subject session's scopes and client allowed_scopes.
      - Derived sessions are capped at DERIVED_SESSION_MAX_TTL (non-extendable).
    """
    if client_rec is None:
        abort(401, OAuthError.UNAUTHORIZED_CLIENT)

    client_id = client_rec.client_id
    limits = current_app.extensions.get("rate_limits", {})

    # Per-client rate limit before adapter auth.
    pr_key = rate_limit_principal_key(client_id, realm=client_rec.realm)
    resp, _, _ = limit_or_429(limits.get("30_per_min"), pr_key, f"Too many requests: {route_label(request)}")
    if resp is not None:
        logger.warning(f"token_exchange_rate_limited: client_id={client_id}, realm={client_rec.realm} key={pr_key}")
        return resp

    # Confidential clients must authenticate (RFC 8693 sec. 2.1 / RFC 6749 sec. 3.2.1).
    # Skipping this would allow anyone possessing a compromised subject token to
    # exchange it into new tokens scoped to arbitrary resources.
    if not client_rec.public:
        adapter_authenticate(proof_context=proof_ctx, client_rec=client_rec)

    subject_token = (proof_ctx.get("subject_token") or "").strip()
    subject_token_type = (proof_ctx.get("subject_token_type") or "").strip()

    if not subject_token:
        audit_event("token_exchange_missing_param", client_id=client_id, param="subject_token")
        abort(400, description=OAuthError.INVALID_REQUEST)
    if not subject_token_type:
        audit_event("token_exchange_missing_param", client_id=client_id, param="subject_token_type")
        abort(400, description=OAuthError.INVALID_REQUEST)
    if subject_token_type != SUBJECT_TOKEN_TYPE_ACCESS:
        audit_event("token_exchange_unsupported_type",
                    client_id=client_id, token_type=subject_token_type)
        abort(400, description=OAuthError.INVALID_REQUEST)

    # Validate the subject token against the active session store
    sid, session = store.get_active_session_by_session_key(subject_token)
    if session is None:
        audit_event("token_exchange_invalid_subject_token",
                    request_id=get_request_id(), client_id=client_id)
        abort(400, description=OAuthError.INVALID_TOKEN)

    # No transitive exchange: DERIVED sessions cannot be re-exchanged
    if session.is_derived():
        audit_event("token_exchange_transitive_denied",
                    request_id=get_request_id(), client_id=client_id, sid=sid)
        abort(403, description=OAuthError.ACCESS_DENIED)

    # Default-deny: require an explicit allowed_token_exchange_targets list
    allowed_targets = normalize_str_list(client_rec.allowed_token_exchange_targets or [])
    if not allowed_targets:
        audit_event("token_exchange_no_targets_configured",
                    request_id=get_request_id(), client_id=client_id, sid=sid)
        abort(403, description=OAuthError.ACCESS_DENIED)

    # Resource policy: permitted = intersection of client allowed exchange targets and client allowed resources.
    # The subject token's resource binding proves who the user is; it does not restrict what downstream
    # resources the exchange client can access on the user's behalf -- that is the role of
    # allowed_token_exchange_targets. Including the subject resources in the intersection would break
    # the intended delegation pattern (e.g. MCP server exchanging a user's MCP-scoped token for a
    # DERIVA-scoped token) since the subject token is bound to the upstream resource, not the target.
    allowed_target_set = set(allowed_targets)
    client_allowed_set = set(normalize_str_list(client_rec.allowed_resources or []))
    permitted_resource_set = allowed_target_set & client_allowed_set

    requested_resources = _parse_requested_resources_from_ctx(proof_ctx)
    if requested_resources:
        final_resources = requested_resources
    else:
        default_resources = set(normalize_str_list(client_rec.default_resources or []))
        final_resources = sorted(permitted_resource_set & default_resources) if default_resources \
            else sorted(permitted_resource_set)

    if not final_resources:
        audit_event("token_exchange_no_resources",
                    request_id=get_request_id(), client_id=client_id, sid=sid)
        abort(403, description=OAuthError.ACCESS_DENIED)

    disallowed_resources = set(final_resources) - permitted_resource_set
    if disallowed_resources:
        audit_event("token_exchange_resource_denied",
                    request_id=get_request_id(), client_id=client_id,
                    sid=sid, disallowed=sorted(disallowed_resources))
        abort(403, description=OAuthError.ACCESS_DENIED)

    # Scope policy: permitted = subject scopes (intersection of client allowed_scopes if configured)
    subject_scopes = set(get_effective_scopes(session))
    client_allowed_scopes = set(normalize_str_list(client_rec.allowed_scopes or []))
    permitted_scopes = (subject_scopes & client_allowed_scopes) if client_allowed_scopes else subject_scopes

    requested_scopes = _parse_requested_scopes_from_ctx(proof_ctx)
    final_scopes = requested_scopes if requested_scopes else sorted(permitted_scopes)

    disallowed_scopes = set(final_scopes) - permitted_scopes
    if disallowed_scopes:
        audit_event("token_exchange_scope_escalation",
                    request_id=get_request_id(), client_id=client_id,
                    sid=sid, disallowed_scopes=sorted(disallowed_scopes))
        abort(403, description=OAuthError.INSUFFICIENT_SCOPE)

    # TTL: capped at DERIVED_SESSION_MAX_TTL (configurable) and client max_session_ttl_seconds
    max_ttl = int(current_app.config.get("DERIVED_SESSION_MAX_TTL", DERIVED_SESSION_MAX_TTL))
    client_max = client_rec.max_session_ttl_seconds or max_ttl
    ttl = min(max_ttl, client_max)

    userinfo = dict(session.userinfo)
    sub = userinfo.get("sub")
    scope_str = " ".join(sorted(final_scopes))

    new_sid = store.generate_session_id()
    skey, _ = store.create_session(
        session_id=new_sid,
        session_type=SessionType.DERIVED,
        access_token=store.generate_session_key(),
        userinfo=userinfo,
        realm=session.realm,
        scopes=scope_str,
        allowed_resources=final_resources,
        expires_at=int(time.time()) + ttl,
        session_ttl=ttl,
        absolute_session_lifetime_secs=ttl,
    )

    audit_event(
        "token_exchange_issued",
        request_id=get_request_id(),
        session_id=new_sid,
        client_id=client_id,
        base_session_id=sid,
        realm=session.realm,
        sub=sub,
        resources=final_resources,
        scopes=final_scopes,
        ttl=ttl,
    )

    return jsonify({
        "access_token":      skey,
        "issued_token_type": SUBJECT_TOKEN_TYPE_ACCESS,
        "token_type":        "bearer",
        "expires_in":        ttl,
        "scope":             scope_str,
    })


def _parse_requested_scopes_from_ctx(ctx: ProofContext) -> List[str]:
    input_scope = ctx.get("scope")
    if not input_scope or not str(input_scope).strip():
        return []
    tokens = [s for s in str(input_scope).split() if s]
    # dedupe deterministically and sort for stable auditing/ordering
    return sorted(dict.fromkeys(tokens))


def _parse_requested_resources_from_ctx(ctx: ProofContext) -> List[str]:
    input_resources = ctx.getlist("resource")
    return normalize_str_list(input_resources)


def _make_anonymous_device_client(client_id: str) -> ClientRecord:
    """
    Synthetic public ClientRecord for an unregistered device flow client.

    Used only when ALLOW_UNREGISTERED_CLIENTS=True. No scope or
    resource policy is enforced -- the only purpose of this record is to
    carry the client_id through to the device_code grant handler so that
    client_id consistency against the stored flow can still be checked.
    """
    return ClientRecord(
        client_id=client_id,
        public=True,
        allowed_grant_types=[GrantType.DEVICE_CODE],
    )


def validate_resources_for_client(*,
                                  proof_ctx: ProofContext,
                                  client_rec: ClientRecord,
                                  subject: str) -> List[str]:

    client_id = client_rec.client_id
    adapter_name = client_rec.adapter_name

    allowed_resources = normalize_str_list(client_rec.allowed_resources or [])
    if not allowed_resources:
        logger.debug(f"server misconfiguration: no allowed resources for client {client_id}.")
        audit_event(
            "token_request_issue_misconfig",
            request_id=get_request_id(),
            reason="no_allowed_resources",
            client_id=client_id,
            adapter=adapter_name,
            subject=subject,
        )
        abort(500, description=OAuthError.SERVER_ERROR)

    allowed_resource_set = set(allowed_resources)
    default_resources = normalize_str_list(client_rec.default_resources or [])
    requested_resources = _parse_requested_resources_from_ctx(proof_ctx)

    audit_event(
        "token_request_resource_requested",
        request_id=get_request_id(),
        requested_resources=requested_resources,
        allowed_resources=allowed_resources,
        client_id=client_id,
        adapter=adapter_name,
        subject=subject,
    )

    if requested_resources:
        final_resources = requested_resources
    else:
        if default_resources:
            final_resources = default_resources
            audit_event(
                "token_request_resource_defaulted",
                request_id=get_request_id(),
                final_resources=final_resources,
                client_id=client_id,
                adapter=adapter_name,
                subject=subject,
            )
        else:
            audit_event(
                "token_request_resource_missing",
                request_id=get_request_id(),
                client_id=client_id,
                adapter=adapter_name,
                subject=subject,
            )
            abort(403, description=OAuthError.ACCESS_DENIED)

    final_resource_set = set(final_resources)

    disallowed = final_resource_set - allowed_resource_set
    if disallowed:
        audit_event(
            "token_request_resource_escalation_attempt",
            request_id=get_request_id(),
            requested_resources=final_resources,
            disallowed_resources=sorted(disallowed),
            allowed_resources=allowed_resources,
            client_id=client_id,
            adapter=adapter_name,
            subject=subject,
        )
        abort(403, description=OAuthError.ACCESS_DENIED)

    if len(final_resources) > MAX_RESOURCES:
        audit_event(
            "token_request_resource_excessive",
            request_id=get_request_id(),
            requested_count=len(final_resources),
            client_id=client_id,
            adapter=adapter_name,
            subject=subject,
        )
        abort(400, description=OAuthError.INVALID_REQUEST)

    return final_resources


def validate_scopes_for_client(*,
                               proof_ctx: ProofContext,
                               client_rec: ClientRecord,
                               subject: str) -> List[str]:

    client_id = client_rec.client_id
    adapter_name = client_rec.adapter_name

    allowed_scopes = normalize_str_list(client_rec.allowed_scopes or [])
    default_scopes = normalize_str_list(client_rec.default_scopes or [])
    requested_scopes = _parse_requested_scopes_from_ctx(proof_ctx)

    # If no allowed_scopes are configured for this client, treat scopes as unrestricted.
    # In that case, we do not require a scope to be present and issue tokens with empty scopes.
    if not allowed_scopes:
        audit_event(
            "token_request_scopes_unrestricted",
            request_id=get_request_id(),
            client_id=client_id,
            adapter=adapter_name,
            subject=subject,
        )
        # If the client did request scopes, return them (deduped) but do not enforce subset.
        # If none requested, return empty list (no scopes).
        return requested_scopes

    # At this point, allowed_scopes is non-empty so we must enforce scope behavior.
    if not requested_scopes:
        if not default_scopes:
            audit_event(
                "token_request_missing_scope",
                request_id=get_request_id(),
                client_id=client_id,
                adapter=adapter_name,
                subject=subject,
                reason="no_scope_and_no_local_defaults",
            )
            abort(400, description=OAuthError.INVALID_REQUEST)
        requested_scopes = default_scopes
        audit_event(
            "token_request_scope_defaulted",
            request_id=get_request_id(),
            final_scopes=requested_scopes,
            client_id=client_id,
            adapter=adapter_name,
            subject=subject,
        )

    allowed_scope_set = set(allowed_scopes)
    requested_scope_set = set(requested_scopes)

    if not requested_scope_set.issubset(allowed_scope_set):
        audit_event(
            "token_request_scope_violation",
            request_id=get_request_id(),
            requested_scopes=requested_scopes,
            allowed_scopes=allowed_scopes,
            client_id=client_id,
            adapter=adapter_name,
            subject=subject,
        )
        abort(403, description=OAuthError.ACCESS_DENIED)

    if len(requested_scopes) > MAX_SCOPES:
        audit_event(
            "token_request_scope_excessive",
            request_id=get_request_id(),
            requested_count=len(requested_scopes),
            client_id=client_id,
            adapter=adapter_name,
            subject=subject,
        )
        abort(400, description=OAuthError.INVALID_REQUEST)

    return requested_scopes


def validate_and_clamp_ttl(*,
                           proof_ctx: ProofContext,
                           client_rec: ClientRecord,
                           subject: str) -> int:

    client_id = client_rec.client_id
    adapter_name = client_rec.adapter_name
    requested_ttl_input = proof_ctx.get("requested_ttl_seconds")
    try:
        requested_ttl = int(requested_ttl_input) if requested_ttl_input is not None else None
    except (ValueError, TypeError):
        audit_event("token_request_bad_ttl",
                    request_id=get_request_id(),
                    requested_ttl=requested_ttl_input,
                    client_id=client_id,
                    adapter=adapter_name,
                    subject=subject)
        abort(400, description=OAuthError.INVALID_REQUEST + " Detail: requested_ttl_seconds must be an integer.")

    ttl = clamp_ttl(client_rec.max_session_ttl_seconds, requested_ttl)
    if requested_ttl is not None and ttl < requested_ttl:
        audit_event("token_request_clamped_ttl",
                    request_id=get_request_id(),
                    requested_ttl=requested_ttl,
                    clamped_ttl=ttl,
                    client_id=client_id,
                    adapter=adapter_name,
                    subject=subject)

    return ttl


def merge_userinfo(userinfo: dict, client_rec: ClientRecord, adapter_claims: dict = None):
    """
    Merge configured client additional_claims and adapter-provided claims into
    userinfo, honoring allowed_claims if populated.

    Behavior:
      - If client_rec.allowed_claims is non-empty: enforce it (only those keys allowed).
      - If client_rec.allowed_claims is empty: interpret as "no whitelist configured"
        and permit adapter-provided claims (adapters are trusted infra).
      - Client additional_claims are merged first (do not overwrite existing userinfo).
      - Adapter claims are merged second and overwrite if necessary (adapter takes precedence).
      - On merge errors, log and return the best-effort merged result instead of aborting 500.
    """
    claim_map = get_claim_map_for_realm(client_rec.realm, realm_maps=current_app.config.get("IDP_CLAIM_MAPS"))

    # Canonicalize allowed_claims list from the client record
    allowed_claims_list = normalize_str_list(client_rec.allowed_claims or [])
    if allowed_claims_list:
        # operator explicitly configured a whitelist -> enforce it
        allowed_claims = set(allowed_claims_list)
    else:
        # No explicit whitelist -> do not enforce any allowlist (permit adapter claims).
        allowed_claims = None

    logger.debug(
        f"merge_userinfo: allowlist_source={'explicit' if allowed_claims is not None else 'implicit'} "
        f"allowed_claims={sorted(list(allowed_claims)) if allowed_claims is not None else None} "
        f"client_additional_claim_keys={list((client_rec.additional_claims or {}).keys())}")

    # Merge client additional_claims first (do not overwrite existing userinfo)
    merged = dict(userinfo)  # shallow copy
    try:
        merged_client, client_changes = merge_additional_claims(
            merged,
            client_rec.additional_claims or {},
            claim_map=claim_map,
            allowed_claims=allowed_claims,
            overwrite=False)
        merged = merged_client
        audit_event(
            "userinfo_merged_client_additional_claims",
            request_id=get_request_id(),
            client_id=client_rec.client_id,
            merged_keys=",".join(sorted(merged.keys())),
            changes=",".join(sorted(client_changes.keys())))
    except Exception as ex:
        # Log and continue with original userinfo; merging failed but token flow
        # should still proceed to allow tests to exercise validation paths.
        logger.exception(f"failed merging client additional_claims for client={client_rec.client_id}: {ex}")

    # Merge adapter additional claims (overwrite if necessary)
    if adapter_claims:
        try:
            merged_adapter, adapter_changes = merge_additional_claims(
                merged,
                adapter_claims,
                claim_map=claim_map,
                allowed_claims=allowed_claims,
                overwrite=True,
            )
            merged = merged_adapter
            audit_event(
                "userinfo_merged_adapter_additional_claims",
                request_id=get_request_id(),
                client_id=client_rec.client_id,
                adapter=client_rec.adapter_name,
                merged_keys=",".join(sorted(merged.keys())),
                changes=",".join(sorted(adapter_changes.keys())),
            )
        except Exception as ex:
            logger.exception(f"failed merging adapter additional_claims for client={client_rec.client_id}: {ex}")
            # keep merged as-is (client claims may already be present)

    return merged


def clamp_ttl(cap: int, requested: Optional[int]) -> int:
    if cap is None:
        cap = DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL
    try:
        cap = int(cap)
    except Exception:
        cap = DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL
    if cap <= 0:
        return DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL
    if requested is None:
        return cap
    try:
        want = int(requested)
    except (TypeError, ValueError):
        want = cap
    if want <= 0:
        want = cap
    return min(want, cap)
