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

import json
import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ----------------------------------------------------------------------
# Fast, precompiled claim resolution with optional JSON-based overrides.
#
# - Dotted paths with:
#     • dict keys:                  "a.b.c"
#     • numeric indices for lists:  "identity_set.0.username"
#     • single-segment wildcard:    "resource_access.*.roles"  (fans out over dict values)
#
# - Base resolver (ClaimResolver):
#     Pre-merges per-realm aliases with global defaults and precompiles paths.
#
# - Override resolver (SimpleOverrideResolver):
#     Reads a JSON structure and precompiles override paths with priority:
#       1) by_realm_key[realm][key]
#       2) by_realm[realm][key]
#       3) by_key[key]
#
# - CombinedClaimResolver:
#     Checks overrides first; if no value, falls back to base.
#
# No runtime string splitting or merging on the hot path.
# ----------------------------------------------------------------------

Token = Tuple[str, Any]  # ("key", "foo") | ("idx", 0) | ("wild", None)

# -----------------------------
# Shared low-level primitives
# -----------------------------
def _dedupe(seq: Iterable[str]) -> List[str]:
    """Stable de-duplication."""
    seen, out = set(), []
    for s in seq:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _compile_path(p: str) -> List[Token]:
    # If it's a namespaced custom-claim key (Auth0 style), keep it literal.
    # e.g., "https://example.com/roles" should be a single dict key.
    if p.startswith("http://") or p.startswith("https://"):
        return [("key", p)]

    toks: List[Token] = []
    for part in p.split("."):
        if part == "*":
            toks.append(("wild", None))
        elif part.isdigit():
            toks.append(("idx", int(part)))
        else:
            toks.append(("key", part))
    return toks



def _get_by_tokens(obj: Any, toks: List[Token]) -> Any:
    """
    Resolve tokens against an object. Returns None if not found.
    Wildcard fans out over dict values and concatenates list results one level.
    """
    i, cur = 0, obj
    while i < len(toks):
        kind, val = toks[i]
        if kind == "key":
            if not isinstance(cur, dict) or val not in cur:
                return None
            cur = cur[val]
            i += 1

        elif kind == "idx":
            if not isinstance(cur, list) or not (0 <= val < len(cur)):
                return None
            cur = cur[val]
            i += 1

        elif kind == "wild":
            if not isinstance(cur, dict):
                return None
            rem = toks[i + 1 :]
            acc: List[Any] = []
            for v in cur.values():
                got = _get_by_tokens(v, rem) if rem else v
                if got is None:
                    continue
                if isinstance(got, list):
                    acc.extend(got)
                else:
                    acc.append(got)
            return acc if acc else None

    return cur


def _non_empty(v: Any) -> bool:
    return v not in (None, "", [])


# ---------------------------------------
# Base resolver: defaults + realm aliases
# ---------------------------------------
class ClaimResolver:
    """
    Fast, precompiled resolver for canonical claim keys.

    It merges per-realm alias lists with global defaults (realm first),
    de-dupes, and compiles to tokens. Runtime `claim()` is just token walking.

    Parameters
    ----------
    defaults : Dict[str, List[str]]
        Global fallback paths for each canonical key.
    aliases : Dict[str, Dict[str, List[str]]]
        Per-realm alias paths for canonical keys, e.g. { "cognito": { "groups": ["cognito:groups"], ... } }.
    """

    __slots__ = ("_compiled", "_keys")

    def __init__(self, *, defaults: Dict[str, List[str]], aliases: Dict[str, Dict[str, List[str]]]):
        compiled: Dict[Tuple[str, str], List[List[Token]]] = {}

        # Collect all keys we might need to resolve
        keys = set(defaults.keys())
        for rmap in aliases.values():
            keys.update(rmap.keys())
        self._keys = keys

        # Precompile for each known realm + a "" realm (no realm; defaults only)
        realms = list(aliases.keys()) + [""]

        for realm in realms:
            for key in keys:
                realm_list = aliases.get(realm, {}).get(key, []) if realm else []
                default_list = defaults.get(key, [])
                merged = _dedupe([*realm_list, *default_list])
                compiled[(realm, key)] = [_compile_path(p) for p in merged]

        self._compiled = compiled

    def claim(self, userinfo: Dict[str, Any], key: str, realm: Optional[str], fallback: Any = None) -> Any:
        cand = self._compiled.get(((realm or ""), key))
        if not cand:
            cand = self._compiled.get(("", key), [])
        for toks in cand:
            val = _get_by_tokens(userinfo, toks)
            if _non_empty(val):
                return val
        return fallback


# --------------------------------------
# JSON-only overrides (precompiled fast)
# --------------------------------------
class SimpleOverrideResolver:
    """
    Precompiled JSON-only overrides with priority:
      1) by_realm_key[realm][key]
      2) by_realm[realm][key]
      3) by_key[key]

    Each entry is a list of dotted paths (same syntax as base resolver).
    """

    __slots__ = ("_compiled",)

    def __init__(self, overrides: Optional[Dict[str, Any]]):
        overrides = overrides or {}
        compiled: Dict[Tuple[str, str], List[List[Token]]] = {}

        by_realm_key: Dict[str, Dict[str, List[str]]] = overrides.get("by_realm_key", {}) or {}
        by_realm:     Dict[str, Dict[str, List[str]]] = overrides.get("by_realm", {}) or {}
        by_key:       Dict[str, List[str]]            = overrides.get("by_key", {}) or {}

        # Enumerate realms & keys seen in overrides
        realms = set(by_realm_key.keys()) | set(by_realm.keys())
        keys: set = set(by_key.keys())
        for rmap in by_realm_key.values():
            keys |= set(rmap.keys())
        for rmap in by_realm.values():
            keys |= set(rmap.keys())

        # Compile (realm, key) combos with priority merge
        for realm in realms:
            for key in keys:
                merged: List[str] = []
                merged += by_realm_key.get(realm, {}).get(key, [])
                merged += by_realm.get(realm, {}).get(key, [])
                merged += by_key.get(key, [])
                if not merged:
                    continue
                merged = _dedupe(merged)
                compiled[(realm, key)] = [_compile_path(p) for p in merged]

        # Also compile generic per-key (no realm; still useful globally)
        for key, paths in by_key.items():
            merged = _dedupe(paths)
            compiled[("", key)] = [_compile_path(p) for p in merged]

        self._compiled = compiled

    def claim(self, userinfo: Dict[str, Any], key: str, realm: Optional[str]) -> Any:
        cand = self._compiled.get(((realm or ""), key)) or self._compiled.get(("", key))
        if not cand:
            return None
        for toks in cand:
            val = _get_by_tokens(userinfo, toks)
            if _non_empty(val):
                return val
        return None


# ------------------------------------------------
# Combined facade (overrides -> base) + JSON loader
# ------------------------------------------------
class CombinedClaimResolver:
    """
    Thin facade: check overrides first; if no value, fall back to base.
    """

    __slots__ = ("base", "over")

    def __init__(self, base: ClaimResolver, over: SimpleOverrideResolver):
        self.base = base
        self.over = over

    def claim(self, userinfo: Dict[str, Any], key: str, realm: Optional[str], fallback: Any = None) -> Any:
        v = self.over.claim(userinfo, key, realm)
        if _non_empty(v):
            return v
        return self.base.claim(userinfo, key, realm, fallback)


def load_claim_overrides_json(path: Optional[str]) -> Dict[str, Any]:
    """
    Load overrides from a JSON file. Returns {} if path is falsy or file missing.
    """
    if not path:
        return {}
    abspath = os.path.abspath(path)
    if not os.path.exists(abspath):
        return {}
    with open(abspath, "r", encoding="utf-8") as f:
        return json.load(f)


def build_combined_resolver(
    *,
    defaults: Dict[str, List[str]],
    aliases: Dict[str, Dict[str, List[str]]],
    overrides_json: Optional[Dict[str, Any]] = None,
) -> CombinedClaimResolver:
    """
    Construct a CombinedClaimResolver from in-memory config.
    """
    base = ClaimResolver(defaults=defaults, aliases=aliases)
    over = SimpleOverrideResolver(overrides_json or {})
    return CombinedClaimResolver(base, over)

# Global fallbacks used for ANY realm (and appended after realm-specific)
OIDC_CLAIM_DEFAULTS: Dict[str, List[str]] = {
    "groups":             ["groups", "https://*/groups", "http://*/groups"],
    "roles":              ["roles", "realm_access.roles", "resource_access.*.roles"],
    "preferred_username": ["preferred_username", "username", "name"],
    "full_name":          ["name"],
    "email":              ["email"],
    "email_verified":     ["email_verified"],
    "id":                 ["sub", "userid"],
    "iss":                ["iss"],
    "aud":                ["aud"],
}

# Realm-specific aliases that take precedence over the defaults above.
# (Populate these per your deployment; examples provided.)
OIDC_CLAIM_ALIASES: Dict[str, Dict[str, List[str]]] = {
    # Amazon Cognito
    "cognito": {
        "groups":             ["cognito:groups"],
        "roles":              ["cognito:roles"],
        "preferred_username": ["cognito:username"],
    },

    # Keycloak
    "keycloak": {
        "groups":             ["groups"],  # via Group Membership mapper
        "roles":              ["realm_access.roles", "resource_access.*.roles"],
    },

    # Okta (requires admin-configured claims)
    "okta": {
        "groups":             ["groups"],
        "roles":              ["roles"],
    },

    # Microsoft Entra ID (Azure AD)
    "azure_ad": {
        "groups":             ["groups"],
        "roles":              ["roles"],  # app roles
    },

    # Auth0: namespaced custom claims are common
    "auth0": {
        "groups":             ["https://*/groups", "http://*/groups"],
        "roles":              ["https://*/roles", "http://*/roles"],
    },

    # Globus Auth
    "globus": {
        # Groups typically come from augmentation via Globus Groups API.
        "preferred_username": ["identity_set.0.username"],
    },
}


__all__ = [
    "ClaimResolver",
    "SimpleOverrideResolver",
    "CombinedClaimResolver",
    "load_claim_overrides_json",
    "build_combined_resolver",
    "OIDC_CLAIM_DEFAULTS",
    "OIDC_CLAIM_ALIASES",
]
