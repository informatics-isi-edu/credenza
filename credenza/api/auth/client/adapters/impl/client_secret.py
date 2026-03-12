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
import time
from dataclasses import dataclass
from typing import Dict, Any, Optional, Iterable
from ......api.common.util import parse_basic_auth
from ......api.common.errors import OAuthError
from ......api.common.crypto import verify_secret_candidate
from ..adapter import (
    AdapterInterface,
    AdapterConfig,
    register_adapter,
    ProofContext,
    Subject,
    AdapterResult,
    AdapterAuthError,
    AdapterError,
)

@dataclass(frozen=True)
class ClientSecretConfig(AdapterConfig):
    client_id: str
    client_secret: Optional[str] = None
    client_secret_hash: Optional[str] = None
    client_secret_hash_scheme: Optional[str] = None


@register_adapter
class ClientSecretAdapter(AdapterInterface[ClientSecretConfig]):

    ADAPTER_NAME = "client_secret"
    SUPPORTED_AUTH_METHODS = ("client_secret_basic", "client_secret_post")


    def __init__(self, config: ClientSecretConfig):
        super().__init__(config)


    @classmethod
    def from_dict(cls, config: Dict[str, Any], client_id: str) -> ClientSecretAdapter:
        """
        Factory: parse/validate config and return an adapter instance.
        Raises ValueError for invalid config.
        """
        if config.get("client_secret") is None and config.get("client_secret_hash") is None:
            raise ValueError("client_secret or client_secret_hash required for client_secret adapter")

        cfg = ClientSecretConfig(
            adapter_name=cls.ADAPTER_NAME,
            config_dict=config,
            client_id=client_id,
            client_secret=config.get("client_secret"),
            client_secret_hash=config.get("client_secret_hash"),
            client_secret_hash_scheme=config.get("client_secret_hash_scheme"),
        )
        return cls(cfg)


    def authenticate(self,
                     proof_context: ProofContext,
                     allowed_methods: Optional[Iterable[str]] = None) -> AdapterResult:
        """
        Authenticate a confidential client.

        Accepts:
          - HTTP Basic Authorization header: Authorization: Basic base64(client_id:client_secret)
          - or form-based client_secret_post: client_id + client_secret in proof_context.form

        On success returns AdapterResult(subject=Subject(...), additional_claims=None, auth_context={...}).
        On failure raises AdapterAuthError(status=401) or AdapterError for internal errors.
        """
        if proof_context is None or not isinstance(proof_context, ProofContext):
            raise AdapterError("invalid proof context")

        # Try HTTP Basic first
        auth_header = proof_context.header("Authorization")
        parsed = None
        method_used = None

        if auth_header:
            parsed = parse_basic_auth(auth_header)
            if parsed:
                method_used = "client_secret_basic"

        # If not basic, try form-based client_secret_post
        if not parsed:
            cid = proof_context.get("client_id")
            secret = proof_context.get("client_secret")
            if cid and secret:
                parsed = {"client_id": cid, "client_secret": secret}
                method_used = "client_secret_post"

        if not parsed:
            # No credentials supplied
            raise AdapterAuthError("client authentication required",
                                   status=401,
                                   error_code=OAuthError.INVALID_REQUEST.code)

        # If policy provided, enforce allowed_methods (fail-fast) by reusing adapter base validator
        if allowed_methods is not None:
            try:
                known, unknown = self.validate_allowed_methods(allowed_methods, raise_on_unknown=True)
            except ValueError as ex:
                # Admin supplied unknown/invalid methods -- treat as configuration/server error
                raise AdapterError(f"invalid allowed_methods configuration: {ex}") from ex

            # If `known` is empty -> allowed_methods was empty/None-equivalent -> no restriction.
            if known:
                # method_used should be one of the canonical names declared on the adapter class
                if method_used is None or method_used not in known:
                    # fail fast: presented auth method not allowed for this client by policy
                    raise AdapterAuthError("authentication method not allowed for this client",
                                           status=401,
                                           error_code=OAuthError.UNAUTHORIZED_CLIENT.code)

        client_id = parsed.get("client_id")
        client_secret = parsed.get("client_secret")

        # Normalize client_id to string for comparison
        if client_id is None:
            raise AdapterAuthError("client authentication required",
                                   status=401,
                                   error_code=OAuthError.INVALID_REQUEST.code)
        client_id = str(client_id)

        if client_id != self.config.client_id:
            # client_id mismatch -> unauthorized
            raise AdapterAuthError("invalid client_id",
                                   status=401,
                                   error_code=OAuthError.UNAUTHORIZED_CLIENT.code)

        # verify secret
        try:
            ok = verify_secret_candidate(client_secret,
                                         plaintext=self.config.client_secret,
                                         stored_hash=self.config.client_secret_hash,
                                         scheme=self.config.client_secret_hash_scheme)
        except Exception as ex:
            # treat unexpected exceptions as internal error
            raise AdapterError(f"secret verification failed: {ex}") from ex

        if not ok:
            raise AdapterAuthError("invalid client_secret",
                                   status=401,
                                   error_code=OAuthError.INVALID_TOKEN.code)

        # Success -> build subject and return AdapterResult
        subject = Subject(provider="client_secret", subject_id=client_id)
        auth_ctx = {
            "name": self.config.adapter_name,
            "client_id": client_id,
            "principal": subject.to_sub(),
            "method": method_used,
            "issued_at": int(time.time()),
        }

        return AdapterResult(subject=subject,
                             additional_claims=None,
                             auth_context=auth_ctx)
