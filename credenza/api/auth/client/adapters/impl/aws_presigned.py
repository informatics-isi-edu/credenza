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
import re
import requests
import time
import logging
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple, Iterable
from urllib.parse import urlparse
from xml.etree import ElementTree as et

from ......api.common.util import retrying_requests_session
from ......api.common.errors import OAuthError
from ..adapter import (
    AdapterInterface,
    AdapterConfig,
    ProofContext,
    AdapterResult,
    AdapterError,
    AdapterAuthError,
    register_adapter,
    Subject
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AwsPresignedConfig(AdapterConfig):
    role_arn: str
    request_attempts: int = 3
    request_backoff_seconds: float = 0.5


@register_adapter
class AwsPresignedAdapter(AdapterInterface[AwsPresignedConfig]):

    ADAPTER_NAME = "aws_presigned"
    SUPPORTED_AUTH_METHODS = ("aws_presigned_getcalleridentity",)

    # Matches STS caller identity ARNs like:
    #   arn:aws:sts::<acct>:assumed-role/<role-name>/<session-name>
    ASSUMED_ROLE_RE = re.compile(r"^arn:aws:sts::(?P<acct>\d{12}):assumed-role/(?P<role>[^/]+)/(?P<session>[^/]+)$")

    # Matches IAM role ARNs like:
    #   arn:aws:iam::<acct>:role/<path>/<role-name>
    #   arn:aws:iam::<acct>:role/<role-name>
    IAM_ROLE_RE = re.compile(r"^arn:aws:iam::(?P<acct>\d{12}):role/(?P<path_and_role>.+)$")

    # Matches generic AWS ARNs embedded in response bodies (fallback when XML parsing fails) like:
    #   arn:aws:sts::<acct>:assumed-role/<role-name>/<session-name>
    #   arn:aws:iam::<acct>:role/<role-name>
    # This is intentionally broad and not role-type specific.
    ARN_FALLBACK_RE = re.compile(r"(arn:aws:[a-z0-9-]+:[^:\s]+:[0-9]*:[^\s\"']+)")

    def __init__(self, config: AwsPresignedConfig):
        super().__init__(config)


    @classmethod
    def from_dict(cls, config: Dict[str, Any], client_id: str) -> AwsPresignedAdapter:
        role = config.get("role_arn")
        if not role:
            raise ValueError("role_arn required for aws_presigned adapter")

        cfg = AwsPresignedConfig(
            client_id=client_id,
            adapter_name=cls.ADAPTER_NAME,
            config_dict=config,
            role_arn=str(role),
            request_attempts=int(config.get("request_attempts") or 3),
            request_backoff_seconds=float(config.get("request_backoff_seconds") or 0.5),
        )
        return cls(cfg)

    def _extract_iam_role_identity(self, arn: str) -> Optional[Tuple[str, str]]:
        if not isinstance(arn, str):
            return None
        m = self.ASSUMED_ROLE_RE.match(arn)
        if m:
            return m.group("acct"), m.group("role")
        m = self.IAM_ROLE_RE.match(arn)
        if m:
            acct = m.group("acct")
            por = m.group("path_and_role")
            role_name = por.split("/")[-1] if por else por
            return acct, role_name
        return None

    def _extract_arn_from_xml(self, xml_text: str) -> Optional[str]:
        try:
            root = et.fromstring(xml_text or "")
        except et.ParseError:
            return None
        for elem in root.iter():
            if elem.tag.endswith("Arn"):
                arn = (elem.text or "").strip()
                if arn:
                    return arn
        return None

    def _extract_error_from_xml(self, xml_text: str) -> tuple:
        try:
            root = et.fromstring(xml_text or "")
        except et.ParseError:
            return None, None
        code = None
        msg = None
        for elem in root.iter():
            if elem.tag.endswith("Code"):
                code = (elem.text or "").strip()
            elif elem.tag.endswith("Message"):
                msg = (elem.text or "").strip()
        return code, msg


    def _get_caller_identity_via_presigned(self, proof_context: ProofContext, url: str, timeout=(2.0, 3.0)):
        """
        Call presigned URL using retrying_requests_session() and return:
          (caller_arn_or_raise, response_or_raise, status_or_raise)

        Raise AdapterAuthError for 4xx client errors, AdapterError for 5xx / transport errors.
        """
        rid = proof_context.request_id
        ip = proof_context.client_ip

        # retrying_requests_session retries on connect/read and configured 5xx codes.
        sess = retrying_requests_session(total=self.config.request_attempts,
                                         backoff_factor=self.config.request_backoff_seconds)
        resp = None
        try:
            resp = sess.get(url, timeout=timeout)
        except requests.Timeout:
            logger.warning(f"get_caller_identity: timeout after retries rid={rid} ip={ip}")
            raise AdapterError("timeout calling presigned URL")
        except requests.RequestException as ex:
            logger.warning(f"get_caller_identity: request error after retries: {ex} rid={rid} ip={ip}")
            raise AdapterError(f"error calling presigned URL: {ex}")
        finally:
            try:
                sess.close()
            except Exception:
                pass

        if resp.status_code != 200:
            err_code, err_msg = self._extract_error_from_xml(resp.text or "")
            hdrs = resp.headers or {}
            req_id = hdrs.get("x-amzn-RequestId") or "-"
            ext_req_id = hdrs.get("X-Amz-Sts-Extended-Request-Id") or "-"
            final_url = resp.url or url
            aws_host = urlparse(final_url).netloc if final_url else "-"
            logger.warning(
                f"get_caller_identity: http {resp.status_code} rid={rid} ip={ip} "
                f"aws_request_id={req_id} aws_ext_req_id={ext_req_id} aws_host={aws_host} "
                f"aws_error_code={err_code or '-'} aws_error_msg={err_msg or '-'}"
            )
            if 400 <= resp.status_code < 500:
                # client-supplied presigned URL is invalid or unauthorized
                # Map to invalid_token: the subject_token/presigned_url proved invalid for identity resolution
                raise AdapterAuthError(
                    "presigned URL returned client error",
                    status=resp.status_code,
                    error_code=OAuthError.INVALID_TOKEN.code
                )
            # 5xx / other server-level errors
            raise AdapterError(f"presigned URL returned error status {resp.status_code}")

        caller_arn = self._extract_arn_from_xml(resp.text)
        if not caller_arn:
            m = self.ARN_FALLBACK_RE.search(resp.text or "")
            if m:
                caller_arn = m.group(1)

        if not caller_arn:
            raise AdapterAuthError("could not determine caller identity from presigned response",
                                   status=401,
                                   error_code=OAuthError.INVALID_TOKEN.code)

        return caller_arn, resp, 200


    def authenticate(self,
                     proof_context: ProofContext,
                     allowed_methods: Optional[Iterable[str]] = None) -> AdapterResult:
        """
        Proof-driven authenticate() entrypoint.

        Expects the presigned URL (or subject_token) in the request form:
          - form field 'presigned_url' or 'subject_token' or 'subject_token_value'

        On success returns AdapterResult with:
          - subject: Subject(provider="aws", subject_id=role_arn)
          - additional_claims: None
          - auth_context: proof metadata
          - requested_resource: proof_context.form.get('resource') if present
        """
        if proof_context is None or not isinstance(proof_context, ProofContext):
            raise AdapterError("invalid proof context")

        url = (proof_context.get("presigned_url") or
               proof_context.get("subject_token") or
               proof_context.get("subject_token_value") or "").strip()

        if not url:
            raise AdapterAuthError("missing presigned URL",
                                   status=400,
                                   error_code=OAuthError.INVALID_REQUEST.code)

        detected_method = self.SUPPORTED_AUTH_METHODS[0]

        # Validate allowed methods (permissive semantics)
        known, unknown = type(self).validate_allowed_methods(allowed_methods, raise_on_unknown=False)
        if unknown:
            logger.warning(f"client allowed_methods contains unknown entries: {sorted(unknown)}")

        if allowed_methods and detected_method not in known:
            raise AdapterAuthError("authentication method not allowed for this client",
                                   status=403,
                                   error_code=OAuthError.UNAUTHORIZED_CLIENT.code)

        if "getcalleridentity" not in url.lower():
            raise AdapterAuthError("malformed presigned URL",
                                   status=400,
                                   error_code=OAuthError.INVALID_REQUEST.code)

        caller_arn, resp, status = self._get_caller_identity_via_presigned(proof_context, url)

        caller_ident = self._extract_iam_role_identity(caller_arn)
        if not caller_ident:
            logger.info(f"aws:get_caller_identity could not parse caller_arn={caller_arn}")
            raise AdapterAuthError("unrecognized caller ARN",
                                   status=401,
                                   error_code=OAuthError.INVALID_TOKEN.code)

        acct, role_name = caller_ident

        role_arn = self.config.role_arn
        config_ident = self._extract_iam_role_identity(role_arn)

        if config_ident != caller_ident:
            logger.info(f"aws:get_caller_identity result {caller_ident} "
                        f"does not match configuration {config_ident}")
            raise AdapterAuthError("caller identity does not match configured role",
                                   status=403,
                                   error_code=OAuthError.ACCESS_DENIED.code)

        try:
            subject = Subject(provider="aws", subject_id=role_arn)
        except Exception as ex:
            raise AdapterError(f"invalid subject for role_arn={role_arn}: {ex}") from ex

        auth_context = {
            "name": self.config.adapter_name,
            "method_used": detected_method,
            "client_id": self.config.client_id,
            "principal": subject.to_sub(),
            "caller_arn": caller_arn,
            "issued_at": int(time.time()),
        }

        logger.info(f"aws:get_caller_identity verified: role_arn={role_arn} account={acct}")

        return AdapterResult(subject=subject,
                             additional_claims=None,
                             auth_context=auth_context)
