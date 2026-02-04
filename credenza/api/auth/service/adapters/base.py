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
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Union, Any

"""
Core types and interface for 'service' (non-human) authentication adapters.

Design goals:
- Keep the base layer LIGHT: only enforce minimal, generic invariants.
- Push provider-specific validation (e.g., AWS ARN shapes) into adapters.
- Use dataclasses with immutability (frozen=True) and slots for safety/perf.
"""

DEFAULT_SERVICE_AUTH_URN = "urn:credenza:service:auth"
DEFAULT_MAX_TTL = 1800
DEFAULT_MAX_ABSOLUTE_LIFETIME = 86400

FormType = Mapping[str, Union[str, List[str]]]

_MAX_ID_LEN = 512
_MAX_LIST_LEN = 128
_MAX_TOKEN_LEN = 256
_MAX_REALM_LEN = 64  # reasonable bound for realm/tenant/env labels
_MAX_EMAIL_LEN = 254  # reasonable bound for email address labels

def _not_empty(s: Optional[str], name: str) -> str:
    if not s:
        raise ValueError(f"{name} is required")
    return s


def _no_ws(s: str, name: str) -> None:
    if any(c.isspace() for c in s):
        raise ValueError(f"{name} must not contain whitespace")


def _bounded(s: str, name: str, max_len: int = _MAX_ID_LEN) -> None:
    if len(s) > max_len:
        raise ValueError(f"{name} exceeds {max_len} characters")


def _check_tokens(name: str, vals: List[str]) -> List[str]:
    if not vals:
        raise ValueError(f"{name} must not be empty")
    if len(vals) > _MAX_LIST_LEN:
        raise ValueError(f"{name} has too many entries")
    out: List[str] = []
    for v in vals:
        _not_empty(v, f"{name} entry")
        _no_ws(v, f"{name} entry")
        _bounded(v, f"{name} entry", _MAX_TOKEN_LEN)
        out.append(v)
    return out

def find_unique_adapter_binding(key: str, val: str, adapter_config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    matches = [b for b in (adapter_config or {}).get("bindings", []) if isinstance(b, dict) and b.get(key) == val]
    if not matches:
        return None
    if len(matches) > 1:
        raise ValueError(f"Multiple bindings matched {key}={val}")
    return matches[0]


@dataclass(frozen=True)
class ProofContext:
    """
    Snapshot of the incoming request visible to adapters.

    `form`: mapping of request form fields. Values may be str or List[str]
            (preserve multiplicity by building this from request.form.to_dict(flat=False)).
    `headers`: case-insensitive mapping of HTTP headers.
    """
    form: FormType
    headers: Mapping[str, str]

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
class ServiceSubject:
    """
    Canonical non-human principal.

    provider:   short label ("aws", "sp", "k8s", "gcp", "azure", ...)
    subject_id: provider-specific identifier (e.g., AWS role ARN, client_id, k8s ns/sa)
    """
    provider: str
    subject_id: str

    def __post_init__(self) -> None:
        _not_empty(self.provider, "ServiceSubject.provider")
        _not_empty(self.subject_id, "ServiceSubject.subject_id")
        _no_ws(self.provider, "ServiceSubject.provider")
        _no_ws(self.subject_id, "ServiceSubject.subject_id")
        _bounded(self.provider, "ServiceSubject.provider", 32)
        _bounded(self.subject_id, "ServiceSubject.subject_id", _MAX_ID_LEN)
        # NOTE: Any provider-specific shape checks belong in the adapter.

    def to_sub(self) -> str:
        """Produce the stored/returned `sub` value used by resource servers."""
        return f"{DEFAULT_SERVICE_AUTH_URN}:{self.provider}:{self.subject_id}"


@dataclass(frozen=True)
class ServiceAuthorization:
    """
    Authorization envelope derived by the adapter mapping for this subject.
    - `scopes`    : list of OAuth-like scope tokens
    - `resources` : list of intended resources (IDs or URN/URI-ish strings)
    - `groups`    : optional list of group identifiers for downstream ACLs
    - `name`      : optional free-form service account identifier (no strict validation here)
    - `email`     : optional contact/owner email (no strict validation here)
    - `realm`     : tenant/env/namespace for isolation (NOT an OP/issuer); defaults to "credenza"
    """
    scopes: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    name: Optional[str] = None
    email: Optional[str] = None
    realm: str = "credenza"

    def __post_init__(self) -> None:
        object.__setattr__(self, "scopes", _check_tokens("scopes", self.scopes))
        object.__setattr__(self, "resources", _check_tokens("resources", self.resources))
        object.__setattr__(self, "groups", _check_tokens("groups", self.groups) if self.groups else [])
        # name validation (lightweight label: bounded)
        if self.name:
            _bounded(self.name, "name", _MAX_ID_LEN)
            object.__setattr__(self, "name", self.name)
        # email validation (lightweight label: no whitespace, bounded)
        if self.email:
            _no_ws(self.email, "email")
            _bounded(self.email, "email", _MAX_EMAIL_LEN)
            object.__setattr__(self, "email", self.email)
        # realm validation (lightweight label: non-empty, no whitespace, bounded)
        r = _not_empty(self.realm, "realm")
        _no_ws(r, "realm")
        _bounded(r, "realm", _MAX_REALM_LEN)
        object.__setattr__(self, "realm", r)


@dataclass(frozen=True)
class ServicePolicy:
    """Normalized policy knobs provided by the adapter for issuance."""
    default_scopes: List[str] = field(default_factory=list)
    max_ttl_seconds: int = DEFAULT_MAX_TTL
    absolute_lifetime_seconds: int = DEFAULT_MAX_ABSOLUTE_LIFETIME


@dataclass(frozen=True)
class ServiceIssueResult:
    """
    Output from an adapter after verifying the caller's proof.

    - `subject`     : normalized non-human principal
    - `authz`       : scopes/resources/groups/owner/email/realm for downstream authz
    - `proof`       : minimal, non-secret record of what was verified (e.g., {"type": "...", "principal": "...", "issued_at": ...})
    - `policy`      : normalized issuance policy (default_scopes, max_ttl_seconds) supplied by adapter
    - `realm`       : tenant/env/namespace for the issued session (defaults to "credenza" if adapter didn't override)
                      Note: for service sessions this is NOT an OIDC issuer; it's a Credenza namespace.
    """
    subject: ServiceSubject
    authz: ServiceAuthorization
    proof: Dict[str, object]
    policy: ServicePolicy = field(default_factory=ServicePolicy)
    realm: str = "credenza"

    def __post_init__(self) -> None:
        if not isinstance(self.proof, dict) or not self.proof.get("type"):
            raise ValueError("proof must include a non-empty 'type'")
        # realm validation (same rules as above)
        r = _not_empty(self.realm, "realm")
        _no_ws(r, "realm")
        _bounded(r, "realm", _MAX_REALM_LEN)
        object.__setattr__(self, "realm", r)


class ServiceAuthAdapter(ABC):
    """
    Implementations verify a specific 'service' proof and map it into (subject, authz, proof, realm).

    Required methods:
      - name()                  : adapter name
      - matches(ctx)            : cheap predicate to decide if this adapter handles the request
      - verify_and_map()        : perform full verification + mapping; raise on failure
    """

    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def matches(self, ctx: ProofContext) -> bool:
        ...

    @abstractmethod
    def verify_and_map(self, ctx: ProofContext, config: Dict) -> ServiceIssueResult:
        ...
