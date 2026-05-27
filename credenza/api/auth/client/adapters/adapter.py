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
from enum import Enum
from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import (
    Union,
    Type,
    TypeVar,
    Generic,
    ClassVar,
    Tuple,
    Iterable,
    Set
)
from ...client import DEFAULT_CLIENT_AUTH_URN
from .....api.common.validators import (
    validate_non_empty,
    validate_no_whitespace,
    validate_bounded
)

"""
Core types and interface for (non-human) client authentication adapters.

Design goals:
- Keep the base layer LIGHT: only enforce minimal, generic invariants.
- Push provider-specific validation (e.g., AWS ARN shapes) into adapters.
- Use dataclasses with immutability (frozen=True) and slots (if possible) for safety/perf.
- Provide a single canonical runtime entrypoint: authenticate(ProofContext, allowed_methods) -> AdapterResult.
"""


@dataclass(frozen=True)
class AdapterConfig:
    """Immutable, adapter-specific parsed config."""
    client_id: str
    adapter_name: str
    config_dict: Dict[str, Any]


@dataclass(frozen=True)
class ProofContext:
    """
    Snapshot of the incoming request visible to adapters.

    `form`: mapping of request form fields. Values may be str or List[str]
            (preserve multiplicity by building this from request.form.to_dict(flat=False)).
    `headers`: case-insensitive mapping of HTTP headers.
    Additional optional metadata: client_ip, request_id, tls_peer_cert, method.
    """
    form: Mapping[str, Union[str, List[str]]]
    headers: Mapping[str, str]
    client_ip: Optional[str] = None
    request_id: Optional[str] = None
    tls_peer_cert: Optional[str] = None
    method: Optional[str] = None

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        v = self.form.get(key, default)
        if isinstance(v, list):
            return v[0] if v else default
        return v

    def getlist(self, key: str) -> List[str]:
        v = self.form.get(key)
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    def header(self, key: str, default: Optional[str] = None) -> Optional[str]:
        key_l = key.lower()
        for k, v in self.headers.items():
            if k.lower() == key_l:
                return v
        return default


@dataclass(frozen=True)
class Subject:
    """
    Canonical non-human principal.

    provider:   short label ("aws", "sp", "k8s", "gcp", "azure", "client_secret", "mtls" ...)
    subject_id: provider-specific identifier (e.g., AWS role ARN, client_id, k8s ns/sa)
    """
    provider: str
    subject_id: str

    def __post_init__(self) -> None:
        validate_non_empty(self.provider, "Subject.provider")
        validate_non_empty(self.subject_id, "Subject.subject_id")
        validate_no_whitespace(self.provider, "Subject.provider")
        validate_no_whitespace(self.subject_id, "Subject.subject_id")
        validate_bounded(self.provider, "Subject.provider", 32)
        validate_bounded(self.subject_id, "Subject.subject_id")

    def to_sub(self) -> str:
        """Produce the stored/returned `sub` value used by resource servers."""
        return f"{DEFAULT_CLIENT_AUTH_URN}:{self.provider}:{self.subject_id}"


from dataclasses import dataclass
from typing import Mapping, Optional, Dict, Any, List

@dataclass(frozen=True)
class AdapterResult:
    """
    Canonical result returned by any client authentication adapter.

    Represents the outcome of authenticating a non-human principal and
    provides structured information to the token handler.

    Fields
    ------
    subject
        The resolved, validated principal (required).

    auth_context
        Optional implementation-specific context (e.g., proof details,
        provider metadata, verification artifacts, policy information).
        Primarily for auditing and downstream metadata storage -- not a
        substitute for token-handler authorization checks.

    additional_claims
        Optional mapping of normalized claims associated with the principal.
        These are authoritative attributes derived during authentication
        (e.g., allowed scopes, resources, groups, name, email).

    namespace
        Optional adapter-derived isolation namespace (logical partition) for
        the authenticated principal.

        This value represents a verified isolation boundary derived from trusted
        authentication context (e.g., AWS account ID, Kubernetes cluster, tenant
        identifier, service domain).

        Precedence rules (effective namespace resolution):

            adapter_result.namespace
                -> client_rec.namespace
                    -> client_rec.client_id

        If provided, this value takes precedence over any client-level namespace
        because it reflects verified runtime identity information.

        SECURITY NOTES:
        - Adapters MUST NOT derive this value from untrusted request parameters.
        - It must be computed only from verified principal attributes or trusted
          configuration.
        - This value defines session isolation and rate-limiting boundaries and
          therefore must be authoritative.

        Token handlers should compute and persist the effective namespace into
        session metadata for audit and enforcement purposes.
    """

    subject: Subject
    auth_context: Optional[Dict[str, Any]] = None
    additional_claims: Optional[Mapping[str, Any]] = None
    namespace: Optional[str] = None

    def __post_init__(self) -> None:
        if self.namespace is None:
            return
        validate_no_whitespace(self.namespace, "AdapterResult.namespace")
        validate_bounded(self.namespace, "AdapterResult.namespace")


class AdapterError(Exception):
    """Internal adapter error"""
    pass


class AdapterAuthError(Exception):
    """
    Authentication or authorization failure caused by the caller.
    Should map to 401 or 403 depending on context.
    """
    def __init__(self, message: str, status: int = 401, error_code: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.error_code = error_code


C = TypeVar("C", bound=AdapterConfig)

class AdapterInterface(ABC, Generic[C]):
    """
    Unified adapter interface for both confidential (secret) and proof-based flows.

    Implementations MUST:
      - provide ADAPTER_NAME class attribute (string key)
      - provide SUPPORTED_AUTH_METHODS class attribute (tuple[str, ...]) containing canonical (lowercase) method names
      - implement from_dict(config, client_id) -> AdapterInterface (factory that returns a usable adapter instance)
      - implement authenticate(proof_context: ProofContext, allowed_methods: Optional[Iterable[str]] = None) -> AdapterResult

    Notes on the new authenticate contract:
      - The token handler / caller will pass in `allowed_methods` (configured by admin for this client).
      - Adapters MUST perform a cheap local probe (inspect ctx.form/ctx.headers) and
        immediately fail with AdapterAuthError if the detected method is not permitted.
      - This avoids calling expensive network/crypto operations when the presented auth method
        is not allowed by policy.
    """

    # required class-level constants; validated in __init_subclass__
    ADAPTER_NAME: ClassVar[str]
    SUPPORTED_AUTH_METHODS: ClassVar[Tuple[str, ...]]

    def __init__(self, config: C) -> None:
        # Enforce that the config is the correct type at runtime (defensive)
        if not isinstance(config, AdapterConfig):
            raise TypeError("AdapterConfig must be AdapterConfig instance")

        # Enforce that the config is bound to the correct adapter class
        if config.adapter_name != self.ADAPTER_NAME:
            raise TypeError(f"AdapterConfig.adapter_name '{config.adapter_name}' "
                            f"does not match adapter class ADAPTER_NAME '{self.ADAPTER_NAME}'")

        self.config: C = config

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

        # Skip validation for the abstract base itself
        if cls is AdapterInterface:
            return

        # Enforce ADAPTER_NAME
        if not hasattr(cls, "ADAPTER_NAME"):
            raise TypeError(f"{cls.__name__} must define ADAPTER_NAME")

        if not isinstance(cls.ADAPTER_NAME, str) or not cls.ADAPTER_NAME:
            raise TypeError(f"{cls.__name__}.ADAPTER_NAME must be a non-empty string")

        # Enforce SUPPORTED_AUTH_METHODS + canonical form (tuple of lowercase strings)
        if not hasattr(cls, "SUPPORTED_AUTH_METHODS"):
            raise TypeError(f"{cls.__name__} must define SUPPORTED_AUTH_METHODS")

        if not isinstance(cls.SUPPORTED_AUTH_METHODS, tuple):
            raise TypeError(f"{cls.__name__}.SUPPORTED_AUTH_METHODS must be a tuple of strings")

        normalized: List[str] = []
        for m in cls.SUPPORTED_AUTH_METHODS:
            if not isinstance(m, str) or not m:
                raise TypeError(f"{cls.__name__}.SUPPORTED_AUTH_METHODS entries must be non-empty strings")
            normalized.append(m.strip().lower())

        # Replace the tuple with a canonical lowercase tuple on the class to avoid
        # case-sensitivity surprises (this mutates the subclass at definition time).
        cls.SUPPORTED_AUTH_METHODS = tuple(dict.fromkeys(normalized))  # keep order, drop duplicates

    @classmethod
    @abstractmethod
    def from_dict(cls, config: Dict[str, Any], client_id: str) -> AdapterInterface[C]:
        """
        Factory: parse/validate the config and return an instance of the concrete adapter class.

        Subclasses should raise ValueError for invalid config.
        """
        raise NotImplementedError()


    @abstractmethod
    def authenticate(self,
                     proof_context: ProofContext,
                     allowed_methods: Optional[Iterable[str]] = None) -> AdapterResult:
        """
        Validate the provided ProofContext and return AdapterResult on success.

        - `allowed_methods` is the admin-configured iterable (can be None or empty meaning 'no restriction').
        - Implementations SHOULD:
            1. Perform a quick, local inspection of `proof_context` to detect which auth method
               the caller appears to be using (e.g., Authorization header basic vs. client_secret_post,
               presence of presigned_url, TLS client cert hints, etc).
            2. If an auth method is detected and `allowed_methods` is provided and the detected
               method is NOT in allowed_methods, raise AdapterAuthError (fail-fast).
            3. Otherwise, proceed with full verification (may include crypto/network calls).
        - On success return AdapterResult.
        - Raise AdapterAuthError for caller-caused auth failures (map to 4xx).
        - Raise AdapterError for internal/server failures.
        """
        raise NotImplementedError()


    @classmethod
    def declared_auth_methods(cls) -> Set[str]:
        """
        Return the canonical set of SUPPORTED_AUTH_METHODS declared by this adapter class.
        All values are lowercased and unique (enforced in __init_subclass__).
        """
        # Note: cls is a concrete adapter subclass when called.
        return set(cls.SUPPORTED_AUTH_METHODS)


    @classmethod
    def supports_auth_method(cls, auth_method_name: str) -> bool:
        """
        Return True if this adapter class advertises support for the given auth method name.
        Comparison is case-insensitive (we treat declared methods as canonical lowercase).
        """
        if not isinstance(auth_method_name, str):
            raise TypeError("auth_method_name must be a string")
        return auth_method_name.strip().lower() in cls.declared_auth_methods()

    @classmethod
    def validate_allowed_methods(cls,
                                 allowed_methods: Optional[Iterable[str]],
                                 raise_on_unknown: bool = False) -> Tuple[Set[str], Set[str]]:
        """
        Validate a configured allowed_methods collection against this adapter's declared methods.

        Returns (known_methods, unknown_methods).
        If raise_on_unknown is True, raises ValueError when any unknown methods are present.
        """
        if allowed_methods is None:
            allowed_set: Set[str] = set()
        else:
            # Ensure it's iterable and entries are strings (do not coerce non-strings)
            try:
                iterator = iter(allowed_methods)
            except Exception as ex:
                raise TypeError("allowed_methods must be an iterable of strings") from ex

            allowed_set = set()
            for m in iterator:
                if not isinstance(m, str):
                    raise TypeError("allowed_methods entries must be strings")
                allowed_set.add(m.strip().lower())

        declared = cls.declared_auth_methods()
        known = allowed_set & declared
        unknown = allowed_set - declared

        if unknown and raise_on_unknown:
            raise ValueError(f"Unknown token auth methods for adapter {cls.__name__}: {sorted(unknown)}")

        return known, unknown


# Registry holds concrete adapter classes keyed by their ADAPTER_NAME string.
_adapter_registry: Dict[str, Type[AdapterInterface[Any]]] = {}

def register_adapter(adapter_class: Type[AdapterInterface[Any]]):
    """Class decorator to register an adapter implementation by its ADAPTER_NAME.

    Raises RuntimeError on duplicate registration to avoid accidental overrides.
    """
    key = getattr(adapter_class, "ADAPTER_NAME", None)
    if not key:
        raise RuntimeError(
            f"Adapter class {adapter_class.__name__} must define ADAPTER_NAME before registering")

    if key in _adapter_registry:
        raise RuntimeError(
            f"Adapter ADAPTER_NAME collision: '{key}' already registered by {_adapter_registry[key].__name__}")

    _adapter_registry[key] = adapter_class
    return adapter_class


def get_adapter(adapter_key: str) -> Optional[Type[AdapterInterface[Any]]]:
    return _adapter_registry.get(adapter_key)


def list_adapters() -> Dict[str, Type[AdapterInterface[Any]]]:
    return dict(_adapter_registry)
