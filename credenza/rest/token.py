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
from typing import Dict, Tuple, Optional, List, Any
from flask import Blueprint, request, jsonify, abort, current_app
from ..telemetry import audit_event
from ..api.session.storage.session_store import SessionStore, SessionType
from ..api.auth.client.client_registry import ClientRegistry, ClientRecord, DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL
from ..api.auth.client.adapters.adapter import ProofContext, AdapterResult, AdapterAuthError, AdapterError
from ..api.common.claim_mapper import merge_additional_claims, get_claim_map_for_realm
from ..api.common.errors import OAuthError
from ..api.common.util import (
    get_current_session,
    get_request_id,
    limit_or_429,
    route_label,
    ip_rate_limited,
    rate_limit_principal_key,
    parse_basic_auth,
    normalize_str_list,
    perf_logged,
    map_grant_type_to_session_type,
    GrantType
)

logger = logging.getLogger(__name__)

MAX_RESOURCES = 32
MAX_SCOPES = 128

token_blueprint = Blueprint("token", __name__)

@token_blueprint.route("/token", methods=["POST"])
@perf_logged(warn_ms=1000)
@ip_rate_limited()
def issue_token():
    """
    POST /authn/token
      - Requires client_id (Basic auth or form)
      - Uses client registry keyed lookup of client_id
      - Delegates authentication to client_rec.adapter_instance.authenticate(...)
      - On success, issues  session by calling issue(...)
    """
    store: SessionStore = current_app.config["SESSION_STORE"]
    limits = current_app.extensions.get("rate_limits", {})
    client_registry: ClientRegistry = current_app.config["CLIENT_AUTH_REGISTRY"]
    proof_ctx = ProofContext(request.form.to_dict(flat=False), dict(request.headers))

    # Validate the client_id against the client registry and return a valid record if it exists
    client_rec = validate_client(client_registry, proof_ctx)
    client_id = client_rec.client_id

    # Validate grant_type and ensure it is both supported and allowed
    grant_type:GrantType = validate_grant_type(proof_context=proof_ctx, client_rec=client_rec)

    if not client_rec.public:
        ar:AdapterResult = adapter_authenticate(proof_context=proof_ctx, client_rec=client_rec)
        sub = ar.subject.to_sub()
        auth_context = ar.auth_context
        adapter_additional_claims = ar.additional_claims
        metadata: Dict[str, Any] = {"auth_context": auth_context}
        if ar.namespace is not None:
            metadata["namespace"] = ar.namespace
    else: # TODO: authorization code flow or device code flow
        sub = None
        adapter_additional_claims = None
        auth_context = None
        raise NotImplementedError

    # Per-principal/subject limit (rate limiting)
    pr_key = rate_limit_principal_key(sub, realm=client_rec.realm, adapter=client_rec.adapter_name)
    resp, _, _ = limit_or_429(limits.get("60_per_min"), pr_key, f"Too many requests: {route_label(request)}")
    if resp is not None:
        logger.warning(f"token_request_rate_limited: sub={sub}, adapter={client_rec.adapter_name} key={pr_key}")
        return resp

    # Validate resources
    resources = validate_resources_for_client(proof_ctx=proof_ctx, client_rec=client_rec, subject=sub)

    # Validate scopes
    scopes = validate_scopes_for_client(proof_ctx=proof_ctx, client_rec=client_rec, subject=sub)

    # Validate requested TTL and clamp if necessary
    ttl = validate_and_clamp_ttl(proof_ctx=proof_ctx, client_rec=client_rec, subject=sub)

    # Merge any additional claims into userinfo
    userinfo = merge_userinfo({"sub": sub}, client_rec, adapter_additional_claims)

    # Determine session type by grant type
    session_type = map_grant_type_to_session_type(grant_type)

    # Issue the token
    sid, skey, ttl = issue(store=store,
                           session_type=session_type,
                           realm=client_rec.realm,
                           userinfo=userinfo,
                           scopes=scopes,
                           resources=resources,
                           metadata=metadata if metadata else None,
                           ttl=ttl)

    # TODO: token exchange requires additional fields, e.g.:
    # "issued_token_type":"urn:ietf:params:oauth:token-type:access_token",
    # "scopes":"a b c" if issued scopes different than requested
    out = jsonify({"access_token": skey,
                   "token_type": "bearer",
                   "expires_in": ttl})

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

    return out

# TODO: implement RFC7009 semantics
@token_blueprint.route("/revoke", methods=["POST"])
@perf_logged(warn_ms=1000)
@ip_rate_limited()
def revoke_token():  # pragma: no cover
    sid, session = get_current_session()
    store: SessionStore = current_app.config["SESSION_STORE"]

    if not session.is_service():
        audit_event(
            "service_token_revoke_denied",
            session_id=sid,
            realm=session.realm,
            reason="not_a_service_session",
        )
        abort(403, description="only service tokens can be revoked via this endpoint.")

    store.delete_session(sid)

    audit_event(
        "service_token_revoked",
        session_id=sid,
        realm=session.realm,
        sub=session.userinfo.get("sub"),
    )

    return current_app.response_class(status=204)


def issue(*,
          store: SessionStore,
          session_type: SessionType,
          realm: str,
          userinfo: dict,
          scopes: list,
          resources: list,
          metadata: dict,
          ttl:int) -> Tuple[str, str, int]:

    now = int(time.time())

    sid = store.generate_session_id()
    session_key, _session_data = store.create_session(
        session_id=sid,
        session_type=session_type,
        access_token=store.generate_session_key(),
        scopes=scopes,
        realm=realm,
        userinfo=userinfo,
        allowed_resources=resources,
        expires_at=now + ttl,
        session_ttl=ttl,
        metadata=metadata
    )
    return sid, session_key, ttl


def validate_client(client_registry:ClientRegistry, proof_context:ProofContext):
    # Extract client_id: prefer Authorization Basic, else form client_id
    parsed = parse_basic_auth(request.headers.get("authorization"))
    client_id = parsed["client_id"] if parsed else None
    if client_id is None:
        client_id = proof_context.get("client_id")

    # require client_id per policy
    if not client_id:
        audit_event("token_request_missing_client_id", request_id=get_request_id())
        abort(400, description=OAuthError.INVALID_REQUEST)

    # resolve client from registry
    client_rec = client_registry.get(client_id)
    if client_rec is None:
        audit_event("token_request_unknown_client", client_id=client_id)
        abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

    # ensure client is enabled
    if not client_rec.enabled:
        audit_event("token_request_disabled_client", client_id=client_id)
        abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

    return client_rec

def validate_grant_type(proof_context: ProofContext, client_rec: ClientRecord) -> GrantType:
    # Extract grant_type
    grant_type_input = proof_context.get("grant_type") or ""
    grant_type_input = grant_type_input.strip()
    if not grant_type_input:
        audit_event(
            "token_request_missing_grant_type", request_id=get_request_id())
        abort(400, description=OAuthError.INVALID_REQUEST)

    # First, ensure it's a syntactically/semantically known grant type
    try:
        grant_type = GrantType(grant_type_input)
    except ValueError:
        logger.error(f"Unsupported grant type in request: {grant_type_input}")
        audit_event(
            "token_request_unsupported_grant_type_for_client",
            request_id=get_request_id(),
            grant_type=grant_type_input,
            client_id=client_rec.client_id,
            allowed_grants=client_rec.allowed_grant_types,
        )
        abort(400, description=OAuthError.INVALID_REQUEST)

    # Then ensure the parsed grant type is allowed for this client
    allowed_grants = client_rec.allowed_grant_types or []
    if grant_type.value not in allowed_grants and grant_type_input not in allowed_grants:
        audit_event(
            "token_request_invalid_grant_type_for_client",
            request_id=get_request_id(),
            grant_type=grant_type.value,
            client_id=client_rec.client_id,
            allowed_grants=allowed_grants,
        )
        abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

    return grant_type


def adapter_authenticate(proof_context:ProofContext, client_rec: ClientRecord):
    # Get adapter instance from client record (already constructed by registry)
    client_id = client_rec.client_id
    adapter = client_rec.adapter_instance
    if adapter is None:
        logger.error(f"confidential client {client_id} has no valid authentication adapter_instance configured")
        audit_event("token_request_misconfigured_client_adapter", client_id=client_id)
        abort(500, description=OAuthError.SERVER_ERROR)

    # Authenticate via adapter.authenticate (returns an AdapterResult or raises AdapterAuthError/AdapterError)
    try:
        ar: AdapterResult = adapter.authenticate(
            proof_context=proof_context, allowed_methods=client_rec.allowed_auth_methods)
    except AdapterAuthError as e:
        audit_event("token_request_adapter_auth_error",
                    request_id=get_request_id(),
                    client_id=client_id,
                    error_code=e.error_code,
                    error=str(e))
        abort(e.status, description=OAuthError.get(e.error_code))
    except AdapterError as e:
        logger.error(f"adapter error while authenticating client={client_id}: {str(e)}")
        audit_event("token_request_adapter_failure", client_id=client_id, error=str(e))
        abort(500, description=OAuthError.SERVER_ERROR)

    return ar


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
