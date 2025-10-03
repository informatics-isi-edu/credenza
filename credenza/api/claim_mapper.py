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

import os
import json
from copy import deepcopy
from typing import Any, Dict, List, Union

# Minimal, explicit claim mapper:
# - Exact keys only (no wildcards, no indexing)
# - Ordered first-match per key
# - Small provider presets (Cognito, Keycloak, etc.)
# - Per-realm overrides merged on top of defaults/presets

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


def _merge_claim_maps(base: ClaimMap, override: ClaimMap | None) -> ClaimMap:
    """Shallow merge: list for a key is fully replaced by override."""
    merged = deepcopy(base)
    if not override:
        return merged
    for k, v in override.items():
        merged[k] = v
    return merged


def _find_preset_for_realm(realm: str) -> str | None:
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
    Build {realm -> claim_map} by merging:
        DEFAULT_CLAIM_MAP  -> IDP_PRESETS[preset_key]  -> profile['claim_map_overrides']
    Where preset_key is:
      - exact realm match in IDP_PRESETS, else
      - the IDP preset whose name is a substring of the realm (case-insensitive), preferring the longest match.
    Always includes a 'default' entry if not present in profiles.
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


def get_claim_map_for_realm(realm: str | None, realm_maps: Dict[str, ClaimMap]) -> ClaimMap:
    """Pick the map for a realm with fallback to 'default' (or empty dict if absent)."""
    if not realm_maps:
        return {}
    if realm and realm in realm_maps:
        return realm_maps[realm]
    return realm_maps.get("default", {})


def _get_path(obj: Any, path: Path) -> Any:
    """Exact-key navigation. No wildcards, no indexing, no merging."""
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


def resolve_claim(
    userinfo: dict,
    claim_map: ClaimMap,
    key: str,
    default=None,
    *,
    listify: bool = False,
):
    """
    Try each configured path for 'key' in order; return first non-empty value.
    If listify=True and the value is a scalar, wrap it as [value].
    """
    paths = claim_map.get(key, [])
    for candidate in paths:
        val = _get_path(userinfo, candidate)
        if val in (None, "", []):
            continue
        if listify and not isinstance(val, list):
            return [val]
        return val
    return default
