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
from dataclasses import asdict
from typing import Dict, Tuple, Optional, List
from flask import Blueprint, request, jsonify, abort, current_app
from ..api.session.storage.session_store import SessionStore, SessionType
from ..api.common.util import get_current_session, client_ip, limit_or_429, route_label, perf_logged, ip_rate_limited
from ..api.auth.service.adapters.base import ProofContext, ServicePolicy, DEFAULT_SERVICE_AUTH_URN
from ..api.auth.service.adapters.aws_presigned import AwsPresignedAdapter
from ..api.auth.service.adapters.client_secret import ClientSecretAdapter
from ..telemetry import audit_event

"""
REST handler for service token issuance and revocation.
"""

ADAPTERS = [
    AwsPresignedAdapter(),
    ClientSecretAdapter()
]
DEFAULT_MAX_TTL = 1800

service_blueprint = Blueprint("service", __name__)

@service_blueprint.route("/service/token", methods=["POST"])
@service_blueprint.route("/service-token", methods=["POST"])  # optional alias
@perf_logged(warn_ms=1000)
@ip_rate_limited()
def issue_service_token():
    """
    POST /authn/service/token (and optional alias /authn/service-token)
      - Dispatches to the first adapter whose `.matches(ctx)` returns True.
      - Issues an opaque token backed by a 'service' session in the store.
    """
    ctx = ProofContext(request.form.to_dict(flat=False), dict(request.headers))
    store: SessionStore = current_app.config["SESSION_STORE"]
    config: dict = current_app.config["SERVICE_AUTH"]
    limits = current_app.extensions["rate_limits"]

    # Require explicit grant_type
    grant_type = (ctx.get("grant_type") or "").strip()
    if grant_type != DEFAULT_SERVICE_AUTH_URN:
        audit_event("service_token_invalid_grant_type",
                    grant_type=grant_type, route=route_label(request))
        abort(400, description=f"grant_type must be '{DEFAULT_SERVICE_AUTH_URN}'.")

    for adapter in ADAPTERS:
        if not adapter.matches(ctx):
            continue

        adapter_cfg = (config or {}).get("adapters", {}).get(adapter.name(), {}) or {}
        res = adapter.verify_and_map(ctx, adapter_cfg)

        # Post-adapter per-principal limit
        principal = str(res.proof.get("principal") or res.subject.subject_id)
        pr_key = f"principal:{principal}"
        detail = f"Too many requests: {route_label(request)} from: {pr_key}"
        resp, rem_pr, reset_pr = limit_or_429(limits["60_per_min"], pr_key, detail)
        if resp is not None:
            resp.headers.update(limits["60_per_min"].headers(rem_pr, reset_pr))
            return resp

        # Validate scopes
        allowed_scopes = set(res.authz.scopes or [])
        default_scopes = norm_str_list(res.policy.default_scopes)
        scope_raw = ctx.get("scope")

        if not scope_raw or not str(scope_raw).strip():
            if not default_scopes:
                audit_event("service_token_missing_scope",
                            adapter=adapter.name(), principal=principal, reason="no_scope_and_no_local_defaults")
                abort(400, description="scope is required unless default_scopes is configured.")
            req_scopes = default_scopes
        else:
            req_scopes = sorted({s for s in str(scope_raw).split() if s})

        if not set(req_scopes).issubset(allowed_scopes):
            audit_event("service_token_scope_violation",
                        adapter=adapter.name(), principal=principal, requested_scopes=req_scopes,
                        allowed_scopes=sorted(allowed_scopes))
            abort(403, description="one or more requested scopes are not permitted.")

        # Validate audiences
        allowed_aud = set(res.authz.audiences or [])
        if not allowed_aud:
            audit_event("service_token_issue_misconfig",
                        reason="no_allowed_audiences",
                        adapter=adapter.name(), principal=principal)
            abort(500, description="server misconfiguration: no audiences for this principal.")

        req_aud = sorted(set(norm_str_list(ctx.getlist("audience"))))  # dedupe & order
        audit_event("service_token_audience_requested",
                    requested_audiences=req_aud,
                    allowed_audiences=sorted(allowed_aud),
                    adapter=adapter.name(), principal=principal)

        final_aud = req_aud or sorted(allowed_aud)
        disallowed = set(final_aud) - allowed_aud
        if disallowed:
            audit_event("service_token_audience_escalation_attempt",
                        requested_audiences=final_aud,
                        disallowed_audiences=sorted(disallowed),
                        allowed_audiences=sorted(allowed_aud),
                        adapter=adapter.name(), principal=principal)
            abort(403, description="one or more requested audiences are not permitted.")
        if not final_aud:
            abort(403, description="no effective audience available for token issuance.")
        if len(final_aud) > 32:
            audit_event("service_token_audience_excessive",
                        requested_count=len(final_aud),
                        adapter=adapter.name(), principal=principal)
            abort(400, description="too many audience values; reduce the list.")
        if not req_aud:
            audit_event("service_token_audience_defaulted",
                        final_audiences=final_aud,
                        adapter=adapter.name(), principal=principal)
        elif set(req_aud) < allowed_aud:
            audit_event("service_token_audience_narrowed",
                        requested=req_aud, allowed=sorted(allowed_aud),
                        adapter=adapter.name(), principal=principal)

        # Validate requested TTL and clamp if necessary
        requested_ttl_raw = ctx.get("requested_ttl_seconds")
        try:
            requested_ttl = int(requested_ttl_raw) if requested_ttl_raw is not None else None
        except ValueError:
            audit_event("service_token_bad_ttl",
                        raw_value=requested_ttl_raw,
                        adapter=adapter.name(), principal=principal)
            abort(400, description="requested_ttl_seconds must be an integer.")

        ttl = clamp_ttl(res.policy.max_ttl_seconds, requested_ttl)
        if requested_ttl is not None and ttl < requested_ttl:
            audit_event("service_token_clamped_ttl",
                        requested_ttl=requested_ttl,
                        clamped_ttl=ttl,
                        adapter=adapter.name(), principal=principal)

        token, ttl = issue(
            store=store,
            subject=res.subject.to_sub(),
            authz={
                "scopes": req_scopes,
                "audiences": final_aud,
                "groups": res.authz.groups,
                "email": getattr(res.authz, "email", None),
                "name": getattr(res.authz, "name", None),
                "realm": res.realm,
            },
            ttl=ttl,
            proof=res.proof,
            policy=res.policy
        )

        out = jsonify({"access_token": token, "expires_in": ttl})
        audit_event(
            "service_token_issued",
            sub=res.subject.to_sub(),
            audiences=final_aud,
            requested_audiences=req_aud,
            scopes=req_scopes,
            ttl=ttl,
            proof_type=res.proof.get("type"),
            principal=res.proof.get("principal"),
        )
        return out

    # No adapter matched
    audit_event("service_token_no_adapter_match",
                route=route_label(request),
                headers=list(request.headers.keys()))
    abort(400, description="request did not match any supported service auth method.")


@service_blueprint.route("/service/token", methods=["DELETE"])
@service_blueprint.route("/service-token", methods=["DELETE"])  # optional alias
@perf_logged(warn_ms=1000)
@ip_rate_limited()
def revoke_service_token():
    """
    DELETE /authn/service/token (and optional alias /authn/service-token)
      - Revoke the *current* service token (Authorization: Bearer <token>).
      - Deletes its backing service session. Returns 204 on success.
    """
    sid, session = get_current_session()
    store: SessionStore = current_app.config["SESSION_STORE"]

    # Only service tokens are revocable here; user sessions should use user logout
    if session.session_type != SessionType.service:
        audit_event(
            "service_token_revoke_denied",
            session_id=sid,
            realm=session.realm,
            reason="not_a_service_session",
        )
        abort(403, description="only service tokens can be revoked via this endpoint.")

    # Delete session
    store.delete_session(sid)

    audit_event(
        "service_token_revoked",
        session_id=sid,
        realm=session.realm,
        sub=session.userinfo.get("sub"),
    )

    return current_app.response_class(status=204)


def issue(
    store: SessionStore,
    subject: str,
    authz: Dict,
    ttl: int,
    proof: Dict[str, object],
    *,
    policy: Optional[ServicePolicy] = None,
) -> Tuple[str, int]:

    now = int(time.time())

    userinfo = {
        "sub": subject,
        "aud": authz["audiences"],
        "groups": authz["groups"],
        "name": authz.get("name"),
        "email": authz.get("email"),
    }

    metadata = {"proof": proof}
    if policy is not None:
        metadata["service_policy"] = asdict(policy)

    sid = store.generate_session_id()
    session_key, _session_data = store.create_session(
        session_id=sid,
        session_type=SessionType.service,
        access_token=store.generate_session_key(),
        scopes=authz["scopes"],
        realm=authz["realm"],
        userinfo=userinfo,
        expires_at=now + ttl,
        session_ttl=ttl,
        metadata=metadata,
        use_access_token_as_session_key=True,
    )
    return session_key, ttl


def norm_str_list(vals) -> List[str]:
    """Normalize a list-like of strings: trim, drop empties; tolerate None."""
    out: List[str] = []
    if vals is None:
        return out
    if isinstance(vals, str):
        vals = [vals]
    for v in vals:
        s = (str(v) if v is not None else "").strip()
        if s:
            out.append(s)
    return out


def clamp_ttl(cap: int, requested: Optional[int]) -> int:
    if cap <= 0:
        return DEFAULT_MAX_TTL
    if requested is None:
        return cap
    try:
        want = int(requested)
    except (TypeError, ValueError):
        want = cap
    if want <= 0:
        want = cap
    return min(want, cap)
