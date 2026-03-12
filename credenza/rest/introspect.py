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
from flask import Blueprint, request, jsonify, current_app
from ..telemetry import audit_event
from ..api.auth.client.client_registry import ClientRegistry
from ..api.auth.client.adapters.adapter import ProofContext
from ..api.common.claim_mapper import resolve_claim, get_claim_map_for_realm
from ..api.common.util import get_effective_scopes, get_request_resource_args
from .helpers import (
    validate_client,
    adapter_authenticate,
    get_request_id,
    perf_logged,
    limit_or_429,
    route_label,
    ip_rate_limited,
    rate_limit_principal_key
)

logger = logging.getLogger(__name__)

introspect_blueprint = Blueprint("introspect", __name__)

_INACTIVE = {"active": False}

@introspect_blueprint.route("/introspect", methods=["POST"])
@perf_logged(warn_ms=1000)
@ip_rate_limited()
def introspect_token():
    """
    POST /authn/introspect -- RFC 7662 Token Introspection.

    Returns {"active": false} for any unrecognized, expired, or access-denied
    token rather than 4xx, per RFC 7662 Section 2.2.

    Client gating: if the calling client declares allowed_introspection_resources,
    the token must carry at least one of those resources. This lets resource servers
    restrict introspection to tokens scoped to their own resources.
    """
    store = current_app.config["SESSION_STORE"]
    limits = current_app.extensions.get("rate_limits", {})
    client_registry: ClientRegistry = current_app.config["CLIENT_REGISTRY"]
    proof_ctx = ProofContext(request.form.to_dict(flat=False), dict(request.headers))

    # Validate the client
    client_rec = validate_client(client_registry, proof_ctx)

    # Per-client rate limit applied after validation
    pr_key = rate_limit_principal_key(client_rec.client_id, realm=client_rec.realm)
    resp, _, _ = limit_or_429(limits.get("30_per_min"), pr_key, f"Too many requests: {route_label(request)}")
    if resp is not None:
        logger.warning(f"introspect_request_rate_limited: "
                       f"client_id={client_rec.client_id}, realm={client_rec.realm} key={pr_key}")
        return resp

    # Authenticate the calling client (HTTP 4xx on auth failure, per RFC 7662 sec. 2.1)
    if not client_rec.public:
        adapter_authenticate(proof_context=proof_ctx, client_rec=client_rec)

    token = proof_ctx.get("token")
    if not token or not token.strip():
        return jsonify(_INACTIVE)
    token = token.strip()

    # Look up the session by the opaque bearer token (session key)
    sid, session = store.get_active_session_by_session_key(token)
    if sid is None or session is None:
        audit_event(
            "introspect_token_not_found",
            request_id=get_request_id(),
            client_id=client_rec.client_id,
        )
        return jsonify(_INACTIVE)

    # Client introspection gating:
    # If the client declares allowed_introspection_resources, the token's allowed_resources
    # must intersect -- this restricts RSes to only introspecting tokens for their own resources.
    client_introspect_resources = set(client_rec.allowed_introspection_resources)
    if client_introspect_resources:
        token_resources = set(session.allowed_resources or [])
        if not (client_introspect_resources & token_resources):
            audit_event(
                "introspect_client_resource_gating_denied",
                request_id=get_request_id(),
                client_id=client_rec.client_id,
                session_id=sid,
                client_introspection_resources=sorted(client_introspect_resources),
                token_resources=sorted(token_resources),
            )
            return jsonify(_INACTIVE)

    # Resource binding: if the caller supplies a resource param, it must intersect
    # the token's allowed_resources. In legacy mode, substitute LEGACY_DEFAULT_RESOURCE if nothing supplied.
    req_resources = get_request_resource_args(request.form.getlist("resource"))
    if req_resources and session.allowed_resources:
        res_claim = set(session.allowed_resources)
        if not (set(req_resources) & res_claim):
            audit_event(
                "introspect_resource_binding_denied",
                request_id=get_request_id(),
                client_id=client_rec.client_id,
                session_id=sid,
                requested_resources=req_resources,
                token_resources=sorted(res_claim),
            )
            return jsonify(_INACTIVE)

    # Build response: start from session.userinfo (already normalized at session creation),
    # then overlay RFC 7662 structural fields so the RS gets canonical values.
    base_url = current_app.config["BASE_URL"].rstrip("/")
    claim_map = get_claim_map_for_realm(session.realm, realm_maps=current_app.config.get("IDP_CLAIM_MAPS"))
    sub = resolve_claim(session.userinfo, claim_map, "sub", session.userinfo.get("sub"))

    response = dict(session.userinfo)
    response.update({
        "active": True,
        "iss": base_url,
        "sub": sub,
        "aud": session.allowed_resources,
        "exp": session.expires_at,
        "iat": session.created_at,
        "token_type": "Bearer",
        "scope": " ".join(get_effective_scopes(session)),
    })

    audit_event(
        "introspect_token_active",
        request_id=get_request_id(),
        client_id=client_rec.client_id,
        session_id=sid,
        realm=session.realm,
        sub=sub,
        resources=session.allowed_resources,
    )

    return jsonify(response)