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

import os
import json
import logging
from copy import deepcopy
from typing import Any, Dict, List, Tuple, Set, Union, Optional

logger = logging.getLogger(__name__)

"""
Claim mapper and helpers for Credenza.

Purpose
-------
This module centralizes mapping between *canonical claim names* (the keys Credenza
uses internally and in APIs, e.g. "full_name", "email") and *source claim paths*
found in identity provider responses (e.g. "name", "cognito:username", ["realm_access","roles"]).

Goals
-----
- Keep mapping rules explicit and simple: exact-key matches only (no wildcards).
- Support ordered, first-match lookup for a canonical key (claim_map values are ordered lists).
- Provide small provider presets (Cognito, Keycloak) and per-realm overrides via configuration.
- Provide utilities to normalize flat adapter-provided claim dicts into canonical keys,
  and to merge those claims safely into the canonical userinfo object.

Key concepts
------------
- claim_map: Dict[str, List[Path]] where Path is either a string key (flat) or a list of keys
  representing a nested path in a dict (e.g. ["realm_access", "roles"]).
- Normalization: mapping flat adapter keys to canonical keys (used for merging).
- Resolution: render-time lookup where callers ask "give me canonical key X" and the mapper
  tries the canonical top-level value first, then the claim_map fallbacks in order.
- Merge policy: merging additional claims into userinfo is explicit and auditable. The
  merge helpers do not make high-level trust decisions — callers should pass an
  allowlist if they wish to restrict what can be injected.

Why document this module
------------------------
The claim-mapper is intentionally conservative but subtle. Correct use requires:
- knowing whether normalization (eager canonicalization) or render-time resolution is relied upon,
- understanding how nested claim paths are represented,
- being explicit about allowlists when merging to avoid surprising behavior.

This file contains the canonical defaults, presets, and all merge/resolve helpers used across Credenza.
"""

# Global defaults (exact keys only, ordered)
DEFAULT_CLAIM_MAP: Dict[str, List[Union[str, List[str]]]] = {
    "groups": ["groups"],
    "roles":  ["roles", ["realm_access", "roles"]],
    "preferred_username": ["preferred_username", "username", "name"],
    "full_name": ["name"],
    "email": ["email"],
    "email_verified": ["email_verified"],
    "id": ["sub", "userid"],
    "iss": ["iss"],
    "aud": ["aud"],
}

# Minimal provider presets: ONLY typical deviations from base defaults.
IDP_PRESETS: Dict[str, Dict[str, List[Union[str, List[str]]]]] = {
    "cognito": {
        "groups": ["groups", "cognito:groups"],
        "preferred_username": ["preferred_username", "username", "name", "cognito:username"],
        # include roles only if you mint such a custom claim in Cognito:
        # "roles": ["roles", "cognito:roles"],
    },
    "keycloak": {
        "roles": [["realm_access", "roles"], "roles"],
    },
    # "auth0": {
    #     # Put your tenant’s namespaced keys here if desired, e.g.:
    #     # "groups": ["https://example.com/groups", "groups"],
    #     # "roles":  ["https://example.com/roles",  "roles"],
    # }
}

Path = Union[str, List[str]]
ClaimMap = Dict[str, List[Path]]


def load_claim_map(path: str) -> ClaimMap:
    """Optional utility: load a standalone claim-map JSON file (not required in preset/merge flow)."""
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _merge_claim_maps(base: ClaimMap, override: Optional[ClaimMap]) -> ClaimMap:
    """Shallow merge: list for a key is fully replaced by override."""
    merged = deepcopy(base)
    if not override:
        return merged
    for k, v in override.items():
        merged[k] = v
    return merged


def _find_preset_for_realm(realm: str) -> Optional[str]:
    """Return preset key if a known preset name is a substring of realm (case-insensitive).
    If multiple match, choose the longest (most specific) name.
    """
    if not realm:
        return None
    r = realm.lower()
    hits = [name for name in IDP_PRESETS.keys() if name in r]
    if not hits:
        return None
    hits.sort(key=len, reverse=True)  # prefer most specific (longest) match
    return hits[0]


def build_realm_claim_maps(profiles: Dict[str, dict]) -> Dict[str, ClaimMap]:
    """
    Construct a ClaimMap per realm by composing defaults, provider presets, and per-realm overrides.

    The merging order (left -> right) is:
        DEFAULT_CLAIM_MAP  -> IDP_PRESETS[preset_key]  -> profile['claim_map_overrides']

    Selection of a preset_key:
      - If the realm string exactly matches a key in IDP_PRESETS, that preset is used.
      - Otherwise, if any preset name is a substring of realm (case-insensitive), the longest
        matching preset name is chosen (prefer most-specific).
      - If no preset matches, no preset is applied and only defaults + overrides are used.

    Returns a dict mapping realm -> ClaimMap. Always includes a 'default' entry (a deepcopy of
    DEFAULT_CLAIM_MAP) if profiles did not include one.

    Note:
      - This performs shallow merging of lists: if an override contains a key, it replaces the
        entire list for that canonical key.
      - The function is deterministic and safe to call at startup to produce a cached `realm_maps`.
    """
    realm_maps: Dict[str, ClaimMap] = {}

    for realm, prof in (profiles or {}).items():
        base = DEFAULT_CLAIM_MAP

        preset_key = realm if realm in IDP_PRESETS else _find_preset_for_realm(realm)
        if preset_key:
            base = _merge_claim_maps(base, IDP_PRESETS[preset_key])

        claim_map = _merge_claim_maps(base, prof.get("claim_map_overrides"))
        realm_maps[realm] = claim_map

    # Ensure fallback
    if "default" not in realm_maps:
        realm_maps["default"] = deepcopy(DEFAULT_CLAIM_MAP)

    return realm_maps


def get_claim_map_for_realm(realm: Optional[str],
                            realm_maps: Dict[str, ClaimMap]) -> ClaimMap:
    """
    Return the claim map to use for a given realm.

    Behavior:
      - If `realm_maps` is falsy: returns empty dict (no mapping).
      - If `realm` is provided and exists in `realm_maps`, returns realm_maps[realm].
      - Otherwise returns realm_maps['default'] if present, else empty dict.

    Intended use:
      - Call once at the start of a request/flow: claim_map = get_claim_map_for_realm(realm, current_app.config["IDP_CLAIM_MAPS"])
      - Pass the returned ClaimMap to normalization and resolve helpers below.
    """
    if not realm_maps:
        return {}
    if realm and realm in realm_maps:
        return realm_maps[realm]
    return realm_maps.get("default", {})


def _get_path(obj: Any, path: Path) -> Any:
    """
    Navigate `obj` along `path` and return the value or None.

    - If path is a string: treat it as a single top-level key and return obj.get(path) if obj is a dict.
    - If path is a list: descend into nested dicts by sequentially doing cur = cur.get(seg).
    - If at any point the current value is not a dict or the key is missing: return None.
    - No indexing into lists is supported (intentional simplification).

    This is a low-level helper used by resolve_claim and by normalization when dealing with nested paths.
    """
    if isinstance(path, str):
        return obj.get(path) if isinstance(obj, dict) else None
    cur = obj
    for seg in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(seg)
        if cur is None:
            return None
    return cur


def resolve_claim(userinfo: dict,
                  claim_map: ClaimMap,
                  key: str,
                  default=None,
                  *,
                  listify: bool = False):
    """
    Resolve a canonical claim value from userinfo using the claim_map fallbacks.

    Order of resolution:
      1. If userinfo contains the canonical key `key` and its value is non-empty, return it.
      2. Otherwise, iterate the configured paths in claim_map.get(key, []) in order; for each path:
         - If path is a string, return userinfo[path] if present.
         - If path is a list, navigate nested keys via _get_path and return if present.
      3. If nothing found, return `default`.

    Parameters:
      - userinfo: dict (may be the merged result of upstream and adapter/client merges).
      - claim_map: mapping for the realm (see build_realm_claim_maps).
      - key: canonical claim name to resolve (e.g. "full_name").
      - listify: if True, coerce scalar values into a single-element list before returning.

    Rationale:
      - Preferring the canonical top-level value first keeps compatibility with code paths that
        eagerly canonicalize claims on merge.
      - Falling back to claim_map paths preserves flexible, provider-specific mappings.
    """

    # Prefer a canonical top-level value if present
    val = userinfo.get(key)
    if val not in (None, "", []):
        if listify and not isinstance(val, list):
            return [val]
        return val

    # Fall back to configured claim_map paths (preserve existing behavior)
    paths = (claim_map or {}).get(key, [])
    for candidate in paths:
        val = _get_path(userinfo, candidate)
        if val in (None, "", []):
            continue
        if listify and not isinstance(val, list):
            return [val]
        return val

    return default


def _is_json_safe(v: Any) -> bool:
    """Return True if v is JSON-serializable by structural inspection (strings must be keys)."""
    if v is None or isinstance(v, (str, int, float, bool)):
        return True
    if isinstance(v, (list, tuple)):
        return all(_is_json_safe(x) for x in v)
    if isinstance(v, dict):
        # keys must be strings for JSON objects
        return all(isinstance(k, str) and _is_json_safe(val) for k, val in v.items())
    return False


def _normalize_additional_claims(additional_claims: Dict[str, Any],
                                 claim_map: ClaimMap) -> Dict[str, Any]:
    """
    Map a flat additional dict of claims to canonical claim keys.

    Typical input: {"name": "Alice", "email": "...", "cognito:username": "alice-123"}
    Output example (using DEFAULT_CLAIM_MAP): {"full_name": "Alice", "email": "...", "preferred_username": "alice-123"}

    Rules:
      - If an incoming key equals a canonical key, it is kept as-is.
      - Otherwise, if the incoming key equals any *flat* string path listed in a claim_map value
        (e.g. claim_map['full_name'] = ['name']), map it to that canonical key.
      - Nested/list path entries in claim_map (e.g. ["realm_access","roles"]) are ignored here,
        because this function is intended to normalize *flat* mappings only.
      - Single-element list entries are treated as valid shorthand (["name"] -> "name").

    Use case:
      - This is intended for merging a flat additional claims dict into userinfo. It is NOT
        intended for render-time claim resolution (use resolve_claim for that).
    """
    if not additional_claims:
        return {}

    # Build reverse lookup: source_key_str -> canonical_key
    reverse: Dict[str, str] = {}
    for canon, paths in (claim_map or {}).items():
        for p in paths:
            if isinstance(p, str):
                reverse[p] = canon
            elif isinstance(p, list) and len(p) == 1 and isinstance(p[0], str):
                # allow single-element lists as odd-but-supported shorthand
                reverse[p[0]] = canon
            else:
                # skip nested/list paths - don't attempt to match flat keys to nested paths
                pass

    normalized: Dict[str, Any] = {}
    for k, v in additional_claims.items():
        target = reverse.get(k, k)
        normalized[target] = v
    return normalized


def merge_additional_claims(userinfo: Dict[str, Any],
                            additional_claims: Optional[Dict[str, Any]],
                            *,
                            claim_map: ClaimMap,
                            allowed_claims: Optional[Set[str]] = None,
                            overwrite: bool = False,
                            listify_keys: Optional[Set[str]] = None) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Normalize and merge adapter-supplied additional_claims into a canonical userinfo dict.

    Returns a tuple: (merged_userinfo, changes) where `changes` is a dict describing the
    action taken for each canonical key (useful for auditing).

    Parameters:
      - userinfo: shallow-copied base canonical userinfo
      - additional_claims: flat mapping from adapter (strings -> scalars/lists/dicts)
      - claim_map: realm-specific ClaimMap used for normalization
      - allowed_claims: optional set of canonical keys that may be injected. If None => permit all.
      - overwrite: when True, incoming values will overwrite existing values in userinfo on collision.
      - listify_keys: optional set of canonical keys that must be coerced to lists if scalar.

    Behavior summary:
      1. Normalize adapter keys to canonical keys using _normalize_additional_claims.
      2. For each normalized canonical key:
         a. If allowed_claims is provided and key not in allowed_claims -> record skipped_disallowed.
         b. If listify requested, coerce scalars to lists.
         c. If value is not JSON-safe, record skipped_non_json_safe.
         d. If key not in userinfo -> add and record 'add'.
         e. Else -> if overwrite True record 'overwrite', otherwise record 'skipped_existing'.
      3. Return the merged userinfo and the changes dict.

    Auditing:
      - `changes` contains per-key actions to allow transparent auditing of merge operations.
      - Callers should emit audit events after merge with merged.keys() and sorted(changes.keys()).

    Security note:
      - This function performs structural normalization and merging but does not decide trust policy.
      - Callers should enforce an allowlist (canonical names) when untrusted adapters or clients are used.
    """
    merged = dict(userinfo or {})  # shallow copy
    changes: Dict[str, Any] = {}

    logger.debug("claim_map keys: %s", list(claim_map.keys()))

    if not additional_claims:
        return merged, changes

    norm = _normalize_additional_claims(additional_claims, claim_map)
    logger.debug("normalized_additional_claims: %s", norm)

    #  log whether we're enforcing an allowlist (helps with auditing)
    logger.debug("merge_additional_claims: allowed_claims=%s (None => permit all)", allowed_claims)

    for k, v in norm.items():
        # policy allowlist check
        if allowed_claims is not None and k not in allowed_claims:
            changes[k] = {"action": "skipped_disallowed", "attempt": v}
            continue

        # listify if requested
        if listify_keys and k in listify_keys and v is not None and not isinstance(v, list):
            v = [v]

        # JSON-safety check for the incoming value
        if not _is_json_safe(v):
            changes[k] = {"action": "skipped_non_json_safe", "attempt": v}
            continue

        if k not in merged:
            merged[k] = v
            changes[k] = {"action": "add", "value": v}
        else:
            # collision: do not overwrite unless explicitly allowed
            if overwrite:
                prev = merged[k]
                merged[k] = v
                changes[k] = {"action": "overwrite", "prev": prev, "value": v}
            else:
                changes[k] = {"action": "skipped_existing", "existing": merged[k], "attempt": v}

    return merged, changes
