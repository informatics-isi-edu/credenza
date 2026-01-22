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
from __future__ import annotations

import logging
import re
import time
import requests
from typing import Optional, List
from xml.etree import ElementTree as ET
from flask import abort, request
from .base import ProofContext, ServiceAuthAdapter, ServiceIssueResult, ServiceSubject, ServiceAuthorization, \
    ServicePolicy, find_unique_adapter_binding, DEFAULT_MAX_TTL, DEFAULT_MAX_ABSOLUTE_LIFETIME
from .....api.common.util import client_ip, get_correlation_id, retrying_requests_session

"""
AWS presigned GetCallerIdentity (GCI) authentication adapter.

Verifies a presigned STS GetCallerIdentity URL (subject_token) and maps the
derived IAM role ARN to an authorization policy from adapter config.

Behavior:
- HTTP retrieval uses urllib3.Retry via a requests Session:
  * Retries connect/read errors and 5xx only (no 4xx retries).
  * Honors Retry-After.
- XML parsing is namespace-agnostic and extracts <Arn> safely.
- Only supports STS assumed-role callers for mapping to role ARN.
- Logs clear diagnostics for each outcome (no secrets).
- Returns 401 on proof/HTTP problems, 403 when role is not allowed.
"""

logger = logging.getLogger(__name__)

# Matches STS caller identity ARNs like:
#   arn:aws:sts::<acct>:assumed-role/<role-name>/<session-name>
ASSUMED_ROLE_RE = re.compile(
    r"^arn:aws:sts::(?P<acct>\d{12}):assumed-role/(?P<role>[^/]+)/(?P<session>[^/]+)$"
)

def _extract_arn_from_xml(xml_text: str) -> Optional[str]:
    """
    Parse GetCallerIdentityResponse XML and extract the ARN.
    Supports namespace variations by ignoring element namespaces.
    """
    try:
        root = ET.fromstring(xml_text or "")
    except ET.ParseError:
        return None
    for elem in root.iter():
        if elem.tag.endswith("Arn"):
            arn = (elem.text or "").strip()
            if arn:
                return arn
    return None


def _derive_role_arn_from_caller(caller_arn: str) -> Optional[str]:
    """
    Convert an STS caller ARN to an IAM role ARN for mapping:
      caller: arn:aws:sts::<acct>:assumed-role/<role-name>/<session>
      role  : arn:aws:iam::<acct>:role/<role-name>
    """
    m = ASSUMED_ROLE_RE.match(caller_arn or "")
    if not m:
        return None
    return f"arn:aws:iam::{m.group('acct')}:role/{m.group('role')}"


class AwsPresignedAdapter(ServiceAuthAdapter):
    """
    Adapter for AWS presigned STS GetCallerIdentity.

    Expected ctx fields:
      - subject_token: str  (the presigned GCI URL)

    """

    def name(self) -> str:
        return "aws_presigned"

    def matches(self, ctx: ProofContext) -> bool:
        """
        Basic selector: requires a subject_token that looks like a GCI call.
        Being permissive here is fine; verify_and_map() will enforce details.
        """
        tok = (ctx.get("subject_token") or "").lower()
        return bool(tok) and "getcalleridentity" in tok

    def verify_and_map(self, ctx: ProofContext, config: dict) -> ServiceIssueResult:
        """
        Verify AWS presigned GetCallerIdentity, map the derived IAM role to
        authorization, and return a ServiceIssueResult.
        """
        rid = get_correlation_id(request)
        ip = client_ip(request)

        url = ctx.get("subject_token")
        if not url:
            logger.warning(f"get_caller_identity: missing subject_token rid={rid} ip={ip}")
            abort(401)

        sess = retrying_requests_session(
            total=3,                # 1 initial + up to 2 retries
            backoff_factor=0.3,     # ~0.3s, 0.6s (exp), honors Retry-After
            status_forcelist=(500, 502, 503, 504)
        )
        # retrieve the presigned AWS GetCallerIdentity URL data
        try:
            # (connect, read) timeouts: fail fast on hung connects
            resp = sess.get(url, timeout=(2.0, 3.0))
        except requests.Timeout:
            logger.warning(f"get_caller_identity: timeout after retries rid={rid} ip={ip}")
            abort(401)
        except requests.RequestException as ex:
            logger.warning(f"get_caller_identity: request error after retries: {ex} rid={rid} ip={ip}")
            abort(401)
        finally:
            try:
                sess.close()
            except Exception:
                pass

        if resp.status_code != 200:
            # Common 4xx from presigned URLs: SignatureDoesNotMatch / RequestExpired
            logger.warning(f"get_caller_identity: http {resp.status_code} after retries rid={rid} ip={ip}")
            abort(401)

        #  Parse XML, derive role, map
        caller_arn = _extract_arn_from_xml(resp.text)
        if not caller_arn:
            logger.warning(f"get_caller_identity: arn not found in xml rid={rid} ip={ip}")
            abort(401)

        role_arn = _derive_role_arn_from_caller(caller_arn)
        if not role_arn:
            logger.warning(f"get_caller_identity: caller not assumed-role (unsupported) rid={rid} ip={ip} caller_arn={caller_arn}")
            abort(401)

        # Find role binding
        binding = find_unique_adapter_binding("role_arn", role_arn, config)
        if not binding:
            logger.warning(f"get_caller_identity: role not allowed by config rid={rid} ip={ip} role_arn={role_arn}")
            abort(403)

        # Build subject & authz
        subject = ServiceSubject(provider="aws", subject_id=role_arn)
        authz = ServiceAuthorization(
            scopes=binding["scopes"],
            audiences=binding["audiences"],
            groups=binding.get("groups", []),
            email=binding.get("email"),
            name=binding.get("name")
        )
        # Establish proof
        proof = {
            "type": "aws_presigned_gci",
            "principal": role_arn,
            "issued_at": int(time.time()),
            "caller_arn": caller_arn,
        }
        # Adapter-normalized policy hints for issuance
        policy = ServicePolicy(
            default_scopes=binding.get("default_scopes", []) or [],
            max_ttl_seconds=int(binding.get("max_ttl_seconds", DEFAULT_MAX_TTL)),
            absolute_lifetime_seconds=int(binding.get("absolute_lifetime_seconds", DEFAULT_MAX_ABSOLUTE_LIFETIME))
        )

        account = role_arn.split(":")[4]
        logger.info(f"aws:get_caller_identity verified rid={rid} ip={ip} role_arn={role_arn} account={account}")

        return ServiceIssueResult(
            subject=subject,
            authz=authz,
            proof=proof,
            policy=policy,
        )
