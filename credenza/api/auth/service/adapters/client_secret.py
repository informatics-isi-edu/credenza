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
import base64
import hmac
import time
import logging
from flask import abort
from .base import ProofContext, ServiceAuthAdapter, ServiceIssueResult, ServiceSubject, ServiceAuthorization, \
    ServicePolicy, find_unique_adapter_binding, DEFAULT_MAX_TTL, DEFAULT_MAX_ABSOLUTE_LIFETIME

logger = logging.getLogger(__name__)

"""
Client secret service adapter (optional / lower-assurance).

Accepts either:
- auth_method=client_secret_post with form client_id/client_secret, or
- HTTP Basic Authorization: Basic base64(client_id:client_secret)

Principal policy is looked up in adapter_cfg["principals"][client_id].
Requires: config values 'scopes', 'resources' (lists), optional 'groups' (list).
"""

class ClientSecretAdapter(ServiceAuthAdapter):
    def name(self) -> str:
        return "client_secret"

    def matches(self, ctx: ProofContext) -> bool:
        am = (ctx.get("auth_method") or "").lower()
        if am in ("client_secret_basic", "client_secret_post"):
            return True
        # Fallback: Authorization: Basic ...
        authz = ctx.header("Authorization", "")
        return authz.lower().startswith("basic ")

    def _parse_client_secret_post(self, ctx: ProofContext):
        cid = (ctx.get("client_id") or "").strip()
        sec = ctx.get("client_secret") or ""
        if not cid or not sec:
            abort(400)  # malformed/missing fields
        return cid, sec

    def _parse_basic(self, ctx: ProofContext):
        authz = ctx.header("Authorization") or ""
        parts = authz.split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "basic":
            abort(400)
        try:
            raw = base64.b64decode(parts[1], validate=True)
            cid, sec = raw.decode("utf-8").split(":", 1)
        except Exception:
            abort(400)
        cid = cid.strip()
        if not cid:
            abort(400)
        return cid, sec

    def verify_and_map(self, ctx: ProofContext, config: dict) -> ServiceIssueResult:
        am = (ctx.get("auth_method") or "").lower()

        if am == "client_secret_post":
            cid, sec = self._parse_client_secret_post(ctx)
        else:
            # default to Basic if unspecified or client_secret_basic
            cid, sec = self._parse_basic(ctx)

        # Find client_id binding
        binding = find_unique_adapter_binding("client_id", cid, config)
        # Unknown client or secret mismatch -> 401
        if not binding or not hmac.compare_digest(str(binding.get("client_secret") or ""), sec):
            abort(401)

        # Build subject & authz
        try:
            subject = ServiceSubject(provider="client_secret", subject_id=cid)
            authz = ServiceAuthorization(
                scopes=binding.get("scopes", []),
                resources=binding.get("resources", []),
                groups=binding.get("groups", []),
                email=binding.get("email"),
                name=binding.get("name")
            )
        except Exception as e:
            logger.warning(f"Exception while constructing service subject/authorization for adapter binding "
                           f"(check config file for errors): {e}")
            abort(500, "service_adapter_configuration_error")

        # Establish proof
        proof = {
            "type": "client_secret",
            "principal": cid,
            "issued_at": int(time.time()),
        }
        # Adapter-normalized policy hints for issuance
        policy = ServicePolicy(
            default_scopes=binding.get("default_scopes", []) or [],
            max_ttl_seconds=int(binding.get("max_ttl_seconds", DEFAULT_MAX_TTL)),
            absolute_lifetime_seconds=int(binding.get("absolute_lifetime_seconds", DEFAULT_MAX_ABSOLUTE_LIFETIME))
        )

        return ServiceIssueResult(
            subject=subject,
            authz=authz,
            proof=proof,
            policy=policy
        )
