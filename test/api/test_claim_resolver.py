# test_claim_resolver.py
# Requires: pytest
import json
import os
import typing as t
import pytest

from credenza.api.claim_resolver import *

# --------------------------
# Fixtures / sample payloads
# --------------------------

@pytest.fixture
def keycloak_userinfo_only_resource_roles():
    # No realm_access.roles, only resource_access.*.roles so wildcard must pick these up
    return {
        "sub": "k-123",
        "name": "KC User",
        "email": "kc@example.org",
        "resource_access": {
            "api": {"roles": ["apiRole"]},
            "svc": {"roles": ["svcRole1", "svcRole2"]},
        },
        "groups": ["kc-g1", "kc-g2"],
    }

@pytest.fixture
def cognito_userinfo():
    return {
        "sub": "c-123",
        "name": "CG User",
        "email": "cg@example.org",
        "cognito:username": "cg-user",
        "cognito:groups": ["cg-g1", "cg-g2"],
        "cognito:roles": ["cg-r1"],
    }

@pytest.fixture
def auth0_userinfo():
    # Typical namespaced custom claims; adjust domain to match your env
    return {
        "sub": "a0-123",
        "name": "A0 User",
        "email": "a0@example.org",
        "https://example.com/roles": ["rA", "rB"],
        "https://example.com/groups": ["gA", "gB"],
        "nickname": "a0-nick",
    }

@pytest.fixture
def globus_userinfo():
    return {
        "sub": "g-123",
        "name": "Globus User",
        "email": "g@example.org",
        "identity_set": [
            {"id": "idp-1", "username": "u1@campus.edu"},
            {"id": "idp-2, ", "username": "u2@lab.gov"},
        ],
        # groups typically populated via augmentation (not present by default)
    }

@pytest.fixture
def base_resolver():
    # Use module defaults/aliases (edit as your deployment requires)
    return ClaimResolver(defaults=OIDC_CLAIM_DEFAULTS, aliases=OIDC_CLAIM_ALIASES)

# --------------------------
# Base ClaimResolver tests
# --------------------------

def test_default_groups_for_unknown_realm(base_resolver):
    userinfo = {"groups": ["g1", "g2"]}
    out = base_resolver.claim(userinfo, key="groups", realm="unknown", fallback=[])
    assert out == ["g1", "g2"]

def test_keycloak_roles_wildcard_when_realm_roles_missing(base_resolver, keycloak_userinfo_only_resource_roles):
    # For realm="keycloak", aliases include ["realm_access.roles", "resource_access.*.roles"]
    # First candidate missing => wildcard candidate should flatten and return combined roles from all clients.
    out = base_resolver.claim(keycloak_userinfo_only_resource_roles, key="roles", realm="keycloak", fallback=[])
    assert sorted(out) == ["apiRole", "svcRole1", "svcRole2"]

def test_keycloak_groups_direct_claim(base_resolver, keycloak_userinfo_only_resource_roles):
    out = base_resolver.claim(keycloak_userinfo_only_resource_roles, key="groups", realm="keycloak", fallback=[])
    assert out == ["kc-g1", "kc-g2"]

def test_globus_preferred_username_index_path(base_resolver, globus_userinfo):
    # For realm="globus" the alias includes "identity_set.0.username"
    out = base_resolver.claim(globus_userinfo, key="preferred_username", realm="globus", fallback=None)
    assert out == "u1@campus.edu"

def test_non_empty_filter_skips_empty_values(base_resolver):
    # "groups" exists but empty -> should try next candidate or fallback
    userinfo = {"groups": []}
    # No other candidates resolve => fallback used
    out = base_resolver.claim(userinfo, key="groups", realm=None, fallback=["fallback"])
    assert out == ["fallback"]

def test_first_non_empty_wins_not_merged(base_resolver):
    # Demonstrate we don't merge values across *different* candidate paths; first non-empty wins.
    # Here "roles" at top-level exists and is non-empty; wildcard roles present too, but should be ignored.
    userinfo = {
        "roles": ["topR1"],
        "resource_access": {"cli": {"roles": ["cliR"]}},
    }
    out = base_resolver.claim(userinfo, key="roles", realm=None, fallback=[])
    assert out == ["topR1"]  # not ["topR1", "cliR"], because we stop at first non-empty candidate

# --------------------------
# SimpleOverrideResolver tests
# --------------------------

def test_overrides_priority_by_realm_key_overrides_everything(cognito_userinfo):
    overrides = {
        "by_realm_key": {
            "cognito": {
                "groups": ["cognito:groups"]  # enforce cognito-specific path
            }
        },
        "by_realm": {
            "cognito": {
                "groups": ["groups"]  # lower priority than by_realm_key
            }
        },
        "by_key": {
            "groups": ["groups"]      # lowest priority of the three
        }
    }
    ovr = SimpleOverrideResolver(overrides)
    out = ovr.claim(cognito_userinfo, key="groups", realm="cognito")
    assert out == ["cg-g1", "cg-g2"]

def test_overrides_by_realm(auth0_userinfo):
    overrides = {
        "by_realm": {
            "auth0": {
                "roles": ["https://example.com/roles"]
            }
        }
    }
    ovr = SimpleOverrideResolver(overrides)
    out = ovr.claim(auth0_userinfo, key="roles", realm="auth0")
    assert out == ["rA", "rB"]

def test_overrides_by_key_when_realm_not_listed(auth0_userinfo):
    overrides = {
        "by_key": {
            "preferred_username": ["nickname"]
        }
    }
    ovr = SimpleOverrideResolver(overrides)
    out = ovr.claim(auth0_userinfo, key="preferred_username", realm="some-unknown-realm")
    assert out == "a0-nick"

def test_overrides_return_none_when_no_match():
    overrides = {"by_realm_key": {}, "by_realm": {}, "by_key": {}}
    ovr = SimpleOverrideResolver(overrides)
    out = ovr.claim({"x": 1}, key="groups", realm="any")
    assert out is None

# --------------------------
# Combined resolver tests
# --------------------------

def test_combined_uses_override_then_base(cognito_userinfo):
    base = ClaimResolver(defaults=OIDC_CLAIM_DEFAULTS, aliases=OIDC_CLAIM_ALIASES)
    overrides = {
        "by_realm_key": {"cognito": {"groups": ["cognito:groups"]}}
    }
    ovr = SimpleOverrideResolver(overrides)
    comb = CombinedClaimResolver(base, ovr)

    # override present -> use it
    out = comb.claim(cognito_userinfo, key="groups", realm="cognito", fallback=[])
    assert out == ["cg-g1", "cg-g2"]

    # key not overridden -> fall back to base defaults/aliases
    out2 = comb.claim(cognito_userinfo, key="email", realm="cognito", fallback=None)
    assert out2 == "cg@example.org"

def test_combined_with_build_helper(auth0_userinfo):
    comb = build_combined_resolver(
        defaults=OIDC_CLAIM_DEFAULTS,
        aliases=OIDC_CLAIM_ALIASES,
        overrides_json={
            "by_realm": {
                "auth0": { "roles": ["https://example.com/roles"] }
            }
        }
    )
    assert isinstance(comb, CombinedClaimResolver)
    out = comb.claim(auth0_userinfo, key="roles", realm="auth0", fallback=[])
    assert out == ["rA", "rB"]

def test_combined_fallback_value_when_nothing_matches(base_resolver):
    base = base_resolver
    ovr = SimpleOverrideResolver({})
    comb = CombinedClaimResolver(base, ovr)
    out = comb.claim({"nope": 1}, key="email", realm="x", fallback="missing")
    assert out == "missing"

# --------------------------
# JSON loader tests
# --------------------------

def test_load_claim_overrides_json_reads_file(tmp_path):
    cfg = {
        "by_realm_key": {"cognito": {"groups": ["cognito:groups"]}},
        "by_realm": {"keycloak": {"roles": ["realm_access.roles"]}},
        "by_key": {"preferred_username": ["nickname"]},
    }
    p = tmp_path / "overrides.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")

    loaded = load_claim_overrides_json(str(p))
    assert loaded == cfg

def test_load_claim_overrides_json_missing_file_returns_empty(tmp_path):
    missing = tmp_path / "does_not_exist.json"
    loaded = load_claim_overrides_json(str(missing))
    assert loaded == {}

def test_load_claim_overrides_json_falsy_returns_empty():
    loaded = load_claim_overrides_json(None)
    assert loaded == {}

# --------------------------
# Additional behavior checks
# --------------------------

def test_empty_vs_nonempty_precedence_in_overrides():
    # First candidate resolves to empty list -> should advance to next candidate
    overrides = {
        "by_key": {
            "groups": ["empty_here", "groups"]
        }
    }
    ovr = SimpleOverrideResolver(overrides)
    ui = {"empty_here": [], "groups": ["ok"]}
    out = ovr.claim(ui, key="groups", realm="any")
    assert out == ["ok"]

def test_index_out_of_range_is_none(base_resolver):
    ui = {"identity_set": []}
    v = base_resolver.claim(ui, key="preferred_username", realm="globus", fallback=None)
    # globus alias tries identity_set.0.username — should fall back to None here
    assert v is None

def test_unknown_realm_and_key_still_uses_defaults(base_resolver):
    ui = {"sub": "x-1", "email": "u@example.org"}
    # "email" is in global defaults list => should return email
    assert base_resolver.claim(ui, key="email", realm="totally-unknown", fallback=None) == "u@example.org"
