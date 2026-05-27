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
import json
import re
import logging
import hashlib
from urllib.parse import quote, urlparse
from dataclasses import dataclass, field, asdict, replace, fields as _dc_fields
from typing import Dict, List, Optional, Any, Type, Tuple, Iterable,  get_origin as _get_origin, get_args as _get_args
from ...common.validators import validate_bounded
from ...common.util import validate_resource_string, normalize_str_list
from ...common.grant_type import GrantType
from ..client import DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL, DEFAULT_CLIENT_AUTH_MAX_ABSOLUTE_LIFETIME
from .adapters.adapter import (
    AdapterConfig,
    AdapterInterface,
    get_adapter
)

logger = logging.getLogger(__name__)

URN_PREFIX_CLIENT = "urn:credenza:realm:client"
RE_CLIENT_REALM = re.compile(r"^urn:credenza:realm:client:[A-Za-z0-9._%\-]{1,256}$")
RE_REALM_SHORT = re.compile(r"^[A-Za-z0-9._\-]{1,256}$")
MAX_RESOURCE_LEN = 1024
MIN_RESOURCE_LEN = 3


def _normalize_grant_type(value: str) -> str:
    # Resolve via GrantType (handles aliases via _missing_); unknown values pass through unchanged.
    try:
        return GrantType(value.strip())
    except ValueError:
        return value.strip()


def make_client_realm_urn(client_id: str) -> str:
    if not client_id:
        raise ValueError("client_id required")
    safe_id = quote(client_id, safe="A-Za-z0-9._-")
    urn = f"{URN_PREFIX_CLIENT}:{safe_id}"
    validate_bounded(urn, "realm")
    return urn


def _validate_and_resolve_realm(input_realm: Optional[str], client_id: str) -> str:
    """
    Validate a configured realm value or produce the deterministic default.

    - If input_realm is None -> derive via make_client_realm_urn(client_id).
    - If input_realm matches RE_CLIENT_REALM (full URN), accept it.
    - Else if input_realm matches RE_REALM_SHORT, accept it as a short realm token
      (e.g., an oidc profile key).
    - Otherwise raise ValueError.
    """
    if input_realm is None:
        return make_client_realm_urn(client_id)

    if not isinstance(input_realm, str):
        raise ValueError("realm must be a string")

    val = input_realm.strip()
    if not val:
        raise ValueError("realm may not be empty")

    if RE_CLIENT_REALM.match(val):
        return val

    if RE_REALM_SHORT.match(val):
        return val

    raise ValueError(f"invalid realm value for client={client_id}")


def validate_resources_list(values: Iterable[str]) -> List[str]:
    """
    Validate and normalize an iterable of resource strings.
    Returns a deduped, sorted list suitable for storing on ClientRecord.
    Raises ValueError on first invalid entry (fail-fast).
    """
    if not values:
        return []

    seen = {}
    out: List[str] = []
    for v in values:
        if v is None:
            continue
        # allow lists with single string like "a b" to be handled upstream;
        # here we expect already-split entries.
        validated = validate_resource_string(v)
        if validated not in seen:
            seen[validated] = True
            out.append(validated)

    # deterministic order
    return sorted(out)


@dataclass(frozen=True)
class ClientRecord:
    """
    Immutable, validated runtime representation of a configured client.

    A ClientRecord represents a registered application identity (the
    client) that interacts with Credenza. This record is *not* a per-user
    session -- it is the static, admin-configured registration for an
    application and documents that application's authentication and
    authorization policy.

    Clients embodied by ClientRecord may include:
      - Non-interactive machine clients (M2M / service credentials).
      - Interactive applications (web apps, SPAs, mobile apps) that
        perform user-facing OAuth/OIDC authorization flows.
      - Hybrid applications that do both: receive user-authorized sessions
        (authorization_code) and later perform server-side operations or
        token-exchange (client_credentials / token_exchange) on behalf of users.

    Security and behavioral consequences:
      - The ClientRecord controls what grant types, auth methods, scopes,
        and resources the registered app may use.
      - User sessions (interactive logins) and service sessions (tokens issued
        via client authentication or token exchange) are distinct runtime
        entities produced by Credenza -- they are not stored inside ClientRecord.
      - Fields like realm, allowed_scopes, default_scopes, and TTL
        govern the tokens/sessions that Credenza will issue to that client.

    Example: MCP / DERIVA interaction
      1. The MCP app is registered as a ClientRecord (client_id="mcp-app") with
         allowed_grant_types including 'authorization_code' and 'token_exchange'.
      2. A user signs in via Credenza (/authorize). Credenza issues a user
         session (user-scoped) for the interactive flow.
      3. Later, the MCP performs a server-side token exchange using its
         client credentials (a different client entry) to obtain a DERIVA-scoped
         service token. Credenza authenticates the MCP via its adapter,
         validates policy, and issues a service session or exchanged token scoped
         to DERIVA.

    Because ClientRecord is frozen/validated at registry-load time, handlers
    should treat its fields as authoritative configuration and enforce the
    corresponding policy during token issuance.

    -------------------------------------------------------------------------
    Default vs Allowed Authorization Controls
    -------------------------------------------------------------------------

    allowed_scopes / allowed_resources:
        Upper bounds on what the client may request.

    default_scopes / default_resources:
        Optional administrator-defined defaults used when the client
        does not explicitly request scope or resource values.
        These must always be subsets of their corresponding allowed_* lists.

    -------------------------------------------------------------------------
    Session Lifetime Policy
    -------------------------------------------------------------------------

    max_session_ttl_seconds:
        Maximum TTL that may be issued for a single session issuance.
        The token handler clamps requested TTL to this value.

    absolute_session_lifetime_seconds:
        Hard upper bound on the total lifetime of a session.
        A session may not be extended past:
            created_at + absolute_session_lifetime_seconds

        This protects against indefinite refresh or re-issuance even
        if grant flows allow re-authentication.

    -------------------------------------------------------------------------
    Immutability & Trust Model
    -------------------------------------------------------------------------

    ClientRecord instances are frozen and must be treated as trusted,
    validated configuration objects. Request handlers should not use
    defensive getattr patterns on these fields; absence indicates a
    configuration error that should fail fast at registry load time.

    The `fingerprint` field represents a deterministic hash of the
    static configuration and may be used for drift detection or audit.
    """
    client_id: str
    realm: Optional[str] = None
    desc: Optional[str] = None
    enabled: bool = True
    public: bool = False
    adapter_config: Optional[AdapterConfig] = None
    adapter_class: Optional[Type[AdapterInterface]] = None
    adapter_instance: Optional[AdapterInterface] = None
    default_resources: List[str] = field(default_factory=list)
    default_scopes: List[str] = field(default_factory=list)
    additional_claims: Dict[str, Any] = field(default_factory=dict)
    allowed_claims: List[str] = field(default_factory=list)
    allowed_grant_types: List[str] = field(default_factory=list)
    allowed_resources: List[str] = field(default_factory=list)
    allowed_scopes: List[str] = field(default_factory=list)
    allowed_auth_methods: List[str] = field(default_factory=list)
    allowed_redirect_uris: List[str] = field(default_factory=list)
    allowed_introspection_resources: List[str] = field(default_factory=list)
    allowed_token_exchange_targets: List[str] = field(default_factory=list)
    max_session_ttl_seconds: Optional[int] = DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL
    absolute_session_lifetime_seconds: Optional[int] = DEFAULT_CLIENT_AUTH_MAX_ABSOLUTE_LIFETIME

    # Consent UI fields
    require_consent: bool = False
    consent_display_name: str = ""
    consent_labels: Dict[str, str] = field(default_factory=dict)

    # Fingerprint of static client config (computed by loader)
    fingerprint: Optional[str] = None

    def __post_init__(self):
        # resolve/validate the configured realm (or derive deterministic default)
        try:
            resolved = _validate_and_resolve_realm(self.realm, self.client_id)
        except Exception as ex:
            raise ValueError(f"invalid realm for client={self.client_id}: {ex}") from ex

        # replace whatever was passed in with the canonical resolved string
        object.__setattr__(self, "realm", resolved)

        # resolve/validate the configured allowed resources
        try:
            effective_allowed = validate_resources_list(self.allowed_resources)
        except Exception as ex:
            raise ValueError(f"invalid allowed_resources for client={self.client_id}: {ex}") from ex

        object.__setattr__(self, "allowed_resources", effective_allowed)

        # validate default_resources and ensure subset membership
        try:
            effective_defaults = validate_resources_list(self.default_resources)
        except Exception as ex:
            raise ValueError(f"invalid default_resources for client={self.client_id}: {ex}") from ex

        disallowed_defaults = set(effective_defaults) - set(effective_allowed)
        if disallowed_defaults:
            raise ValueError(
                f"default_resources not subset of allowed_resources for client={self.client_id}: "
                f"{sorted(disallowed_defaults)}"
            )
        object.__setattr__(self, "default_resources", effective_defaults)

        #  ensure default_scopes is a subset of allowed_scopes
        effective_allowed_scopes = _normalize_list_field(self.allowed_scopes)
        effective_default_scopes = _normalize_list_field(self.default_scopes)
        disallowed_scope_defaults = sorted(set(effective_default_scopes) - set(effective_allowed_scopes))
        if disallowed_scope_defaults:
            raise ValueError(
                f"default_scopes not subset of allowed_scopes for client={self.client_id}: "
                f"{disallowed_scope_defaults}"
            )
        object.__setattr__(self, "allowed_scopes", effective_allowed_scopes)
        object.__setattr__(self, "default_scopes", effective_default_scopes)

        # normalize allowed_grant_types: expand short aliases to canonical URN forms
        object.__setattr__(self, "allowed_grant_types",
                           [_normalize_grant_type(g) for g in self.allowed_grant_types])

        # normalize allowed_redirect_uris: strip, dedupe, sort; preserve exact case (path is case-sensitive)
        try:
            object.__setattr__(self, "allowed_redirect_uris", normalize_str_list(self.allowed_redirect_uris))
        except ValueError as ex:
            raise ValueError(f"invalid allowed_redirect_uris for client={self.client_id}: {ex}") from ex

        # validate allowed_introspection_resources using the same rules as allowed_resources
        try:
            object.__setattr__(self, "allowed_introspection_resources",
                               validate_resources_list(self.allowed_introspection_resources))
        except ValueError as ex:
            raise ValueError(f"invalid allowed_introspection_resources for client={self.client_id}: {ex}") from ex

    @property
    def adapter_name(self) -> str:
        if self.adapter_instance is not None and isinstance(self.adapter_instance, AdapterInterface):
            return self.adapter_instance.ADAPTER_NAME
        return "none"


@dataclass
class ClientRegistry:
    version: str
    clients: Dict[str, ClientRecord]
    resource_index: Dict[str, ClientRecord] = field(default_factory=dict)

    def get(self, client_id: str) -> Optional[ClientRecord]:  # pragma: no cover
        return self.clients.get(client_id)

    def find_rs_by_resource(self, resource_uri: str) -> Optional[ClientRecord]:
        return self.resource_index.get(resource_uri)


def _validate_adapter_instance(adapter_instance: Any, adapter_class: Type[AdapterInterface], cid: str) -> None:
    """
    Ensure the object returned by adapter_class.from_dict is a usable adapter instance.
    """
    if not isinstance(adapter_instance, adapter_class):
        raise ValueError(f"Adapter factory for client={cid} did not return an instance of {adapter_class!r}")


def _validate_adapter_config(adapter_config: Any, cid: str) -> None:
    """
    Ensure adapter_config is an AdapterConfig instance.
    """
    if not isinstance(adapter_config, AdapterConfig):
        raise ValueError(
            f"Adapter instance for client={cid} has invalid `.config` attribute; must be an AdapterConfig instance")


def _normalize_list_field(value: Any) -> Optional[List[str]]:
    """
    Normalize a list-like field for canonical hashing:
      - If value is falsy, return [].
      - Convert items to strings, strip, lowercase, dedupe, and sort.
    """
    if not value:
        return []

    items = list(value)
    normalized = {str(v).strip().lower() for v in items if v is not None}
    return sorted(normalized)

def client_rec_static_dict(client_rec: ClientRecord) -> Dict[str, Any]:
    data = asdict(client_rec)

    # remove runtime-only
    data.pop("adapter_instance", None)
    data.pop("adapter_class", None)

    # flatten adapter_config
    adapter_cfg = data.get("adapter_config")
    if isinstance(adapter_cfg, dict):
        data["adapter_config"] = adapter_cfg.get("config_dict", adapter_cfg)
    else:
        data["adapter_config"] = None

    return data


def fingerprint_client_record(client_rec: ClientRecord) -> str:
    """
    Deterministic SHA256 fingerprint of the static portions of ClientRecord.

    - Excludes runtime-only fields such as adapter_instance and adapter_class and excludes any existing fingerprint.
    - AdapterConfig is reduced to its `config_dict` mapping (if present) to avoid including non-serializable objects.
    - Normalizes canonical list fields (lowercase, deduped, sorted) so ordering/case differences don't change fingerprint.
    - Uses canonical JSON (sorted keys, compact separators) before hashing.
    """
    # Convert dataclass to dict
    data = client_rec_static_dict(client_rec)

    # Remove any previously present fingerprint (we compute fresh)
    data.pop("fingerprint", None)

    # Normalize all dataclass fields that are list[str]-like to canonical order/lowercase.
    # We inspect the ClientRecord dataclass so this stays correct when fields are added.
    _discovered_list_fields = set()
    for f in _dc_fields(client_rec.__class__):
        fname = f.name
        ftype = f.type
        try:
            origin = _get_origin(ftype)
            args = _get_args(ftype)
        except Exception:
            origin = None
            args = ()

        is_list_of_str = (
                (origin is list or origin is List)
                and args
                and args[0] is str
        )

        # Fallback: treat un-annotated plain lists of strings as list-of-str
        if not is_list_of_str:
            val = data.get(fname)
            if isinstance(val, list) and all((x is None) or isinstance(x, str) for x in val):
                is_list_of_str = True

        if is_list_of_str:
            _discovered_list_fields.add(fname)

    # normalize the discovered fields in the serialized dict
    for lf in _discovered_list_fields:
        data[lf] = _normalize_list_field(data.get(lf))

    # adapter_config is a dict (from asdict); replace with its config_dict if present
    # and canonicalize any nested list-like keys that match discovered fields
    adapter_cfg = data.get("adapter_config")
    if isinstance(adapter_cfg, dict):
        cfg_dict = adapter_cfg.get("config_dict", adapter_cfg)

        if isinstance(cfg_dict, dict):
            cfg_copy = {}
            for k, v in cfg_dict.items():
                if k in _discovered_list_fields:
                    cfg_copy[k] = _normalize_list_field(v)
                else:
                    cfg_copy[k] = v
            data["adapter_config"] = cfg_copy
        else:
            data["adapter_config"] = cfg_dict
    else:
        data["adapter_config"] = None

    # Canonical JSON serialization
    js = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(js.encode("utf-8")).hexdigest()


def load_client_registry(path: str) -> ClientRegistry:
    """
    Load client registry JSON from `path` and instantiate adapters.

    Keyed input expected:
      - top-level `clients` MUST be an object mapping client_key -> client-spec
        (the JSON key is used as the authoritative client_id).
      - each client-spec is a JSON object (operator metadata + adapter block optional).
      - adapter factory contract: AdapterClass.from_dict(config: Dict[str,Any], client_id: str) -> AdapterInterface (instance)
        Note: adapter.from_dict is called with the adapter block and client_id; adapter implementations
        that require the client_id should accept it as the second parameter.
      - adapter instance MUST expose `.config` which is AdapterConfig instance

    Permissive behavior:
      - If `adapter` is absent the client will be recorded as adapterless (adapter_* == None).
      - If an `adapter` block is present the loader will attempt to resolve and instantiate the adapter.
        Any adapter factory/instantiation errors will surface as exceptions (fail-fast).
    """
    logger.debug(f"Attempting to load client authentication registry at {path}")

    try:
        with open(path, "r", encoding="utf-8") as fh:
            registry_data = json.load(fh)
    except FileNotFoundError:
        logger.error(f"client registry file not found at {path}; returning empty registry")
        return ClientRegistry(version="0", clients={})

    clients_spec = registry_data.get("clients")

    if clients_spec is None:
        raise ValueError("client registry missing top-level 'clients' element")
    if not isinstance(clients_spec, dict):
        raise ValueError("client registry 'clients' must be an object")

    clients: Dict[str, ClientRecord] = {}

    for key, spec in clients_spec.items():
        if not isinstance(spec, dict):
            raise ValueError(f"client entry for {key} must be an object")

        # Use the JSON key as the authoritative client_id
        client_id = str(key)

        adapter_spec = spec.get("adapter")
        adapter_class = None
        adapter_instance = None
        adapter_config = None

        # If adapter block exists, attempt instantiation. If missing, client is adapterless.
        if adapter_spec is not None:
            # Resolve adapter class -- will raise if 'adapter_name' missing or unknown
            adapter_name = adapter_spec.get("adapter_name") or adapter_spec.get("name")
            if not adapter_name:
                raise ValueError(f"adapter.adapter_name (or 'name') missing in configuration for client {client_id}")

            adapter_class = get_adapter(adapter_name)
            if not adapter_class:
                raise ValueError(f"No adapter registered for adapter_name={adapter_name} (client={client_id})")

            # Use adapter factory: expect an adapter instance back; pass client_id per new contract
            try:
                adapter_instance = adapter_class.from_dict(adapter_spec, client_id)
            except Exception as e:
                raise RuntimeError(f"Adapter {adapter_class!r}.from_dict failed for client={client_id}: {e}") from e

            # Validate adapter instance type
            _validate_adapter_instance(adapter_instance, adapter_class, client_id)

            # Adapter must expose `.config` that is AdapterConfig instance
            adapter_config = getattr(adapter_instance, "config", None)
            _validate_adapter_config(adapter_config, client_id)

        # Read configured public flag (admins may set); default False
        public_flag = bool(spec.get("public", False))

        # Accept optional configured realm from the spec (use None to derive deterministically)
        input_realm = spec.get("realm")

        consent_labels_spec = spec.get("consent_labels")
        if not isinstance(consent_labels_spec, dict):
            consent_labels_spec = {}

        cr = ClientRecord(
            client_id=client_id,
            realm=input_realm,
            desc=spec.get("desc"),
            enabled=bool(spec.get("enabled", True)),
            public=public_flag,
            adapter_config=adapter_config,
            adapter_class=adapter_class,
            adapter_instance=adapter_instance,
            default_resources=list(spec.get("default_resources") or []),
            default_scopes=list(spec.get("default_scopes") or []),
            additional_claims=spec.get("additional_claims") or {},
            allowed_grant_types=list(spec.get("allowed_grant_types") or []),
            allowed_resources=list(spec.get("allowed_resources") or []),
            allowed_scopes=list(spec.get("allowed_scopes") or []),
            allowed_claims=list(spec.get("allowed_claims") or []),
            allowed_auth_methods=list(spec.get("allowed_auth_methods") or []),
            allowed_redirect_uris=list(spec.get("allowed_redirect_uris") or []),
            allowed_introspection_resources=list(spec.get("allowed_introspection_resources") or []),
            allowed_token_exchange_targets=list(spec.get("allowed_token_exchange_targets") or []),
            max_session_ttl_seconds=spec.get("max_session_ttl_seconds"),
            absolute_session_lifetime_seconds=spec.get("absolute_session_lifetime_seconds"),
            require_consent=bool(spec.get("require_consent", False)),
            consent_display_name=str(spec.get("consent_display_name") or ""),
            consent_labels={str(k): str(v) for k, v in consent_labels_spec.items()},
        )

        # Compute fingerprint for static portions and attach it (dataclasses.replace returns a new instance)
        try:
            fp = fingerprint_client_record(cr)
            cr = replace(cr, fingerprint=fp)
        except Exception as ex:
            raise RuntimeError(f"failed computing fingerprint for client={client_id}: {ex}") from ex

        # store under the authoritative client_id (the JSON key)
        clients[client_id] = cr

    # Build resource -> ClientRecord inverted index for consent delegation lookup
    resource_index: Dict[str, ClientRecord] = {}
    for cr in clients.values():
        for r in cr.allowed_resources:
            if r not in resource_index:
                resource_index[r] = cr

    return ClientRegistry(
        version=str(registry_data.get("version", "0")),
        clients=clients,
        resource_index=resource_index,
    )


# ---------- DB bootstrap / merge helper sketch (ORM-agnostic) -----------------------
def merge_static_registry_to_db(static_registry_path: str,
                                db_lookup_by_client_id,
                                db_upsert_client,
                                delete_missing: bool = False) -> Tuple[int, int, int]:  # pragma: no cover
    """
    Merge static registry file into a backing store.

    Parameters:
      - static_registry_path: path to static JSON registry (keyed).
      - db_lookup_by_client_id: callable(client_id) -> existing_db_record or None
          existing_db_record must minimally expose: client_id, fingerprint (string) or dict with 'fingerprint'
      - db_upsert_client: callable(client_dict) -> upsert result (store/replace)
          the callable will be provided a serializable dict with the client record contents.
      - delete_missing: if True, remove DB clients not present in the static file.

    Returns (created, updated, deleted)
    """
    registry = load_client_registry(static_registry_path)
    created = 0
    updated = 0
    deleted = 0

    static_ids = set(registry.clients.keys())

    # process each static client
    for cid, cr in registry.clients.items():
        fp = cr.fingerprint
        payload = client_rec_static_dict(cr)
        existing = db_lookup_by_client_id(cid)
        if existing is None:
            # create
            db_upsert_client(payload)
            created += 1
            continue

        # existing must expose fingerprint comparison
        existing_fp = (getattr(existing, "fingerprint", None) or
                       (existing.get("fingerprint") if isinstance(existing, dict) else None))
        if existing_fp != fp:
            db_upsert_client(payload)
            updated += 1
        else:
            # no change
            continue

    if delete_missing:
        # try to obtain DB listing if possible; otherwise skip delete step
        try:
            db_all_ids = set()
            if hasattr(db_lookup_by_client_id, "list_all_client_ids") and callable(getattr(db_lookup_by_client_id, "list_all_client_ids")):
                db_all_ids = set(db_lookup_by_client_id.list_all_client_ids())  # type: ignore[attr-defined]
            elif hasattr(db_lookup_by_client_id, "__call__") and hasattr(db_lookup_by_client_id, "db_list_all_client_ids"):
                db_all_ids = set(db_lookup_by_client_id.db_list_all_client_ids())  # type: ignore[attr-defined]
            else:
                db_all_ids = set()
        except Exception:
            db_all_ids = set()

        to_delete = db_all_ids - static_ids
        for cid in to_delete:
            try:
                if hasattr(db_upsert_client, "delete"):
                    db_upsert_client.delete(cid)  # type: ignore[attr-defined]
                else:
                    logger.warning(f"delete_missing=True but db_upsert_client has no delete(); skipping delete of {cid}")
                    continue
                deleted += 1
            except Exception as ex:
                logger.exception(f"failed deleting client {cid} during merge: {ex}")

    return created, updated, deleted
