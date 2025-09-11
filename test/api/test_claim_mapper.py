# Tests for the minimal, overridable claim key mapper
# (supports: string paths with optional '*' wildcards; list-of-segments with str|None;
#  None = wildcard over dict keys + flatten)

import json
import pytest
from credenza.api.claim_mapper import load_claim_map, resolve_claim

@pytest.fixture
def base_claim_map():
    # mirrors the simplified example config
    return {
        "groups": [
            "groups",
            "cognito:groups",
            "https://*/groups",
            "http://*/groups",
        ],
        "roles": [
            "roles",
            ["realm_access", "roles"],
            ["resource_access", None, "roles"],
        ],
        "preferred_username": ["preferred_username", "username", "name"],
        "full_name": ["name"],
        "email": ["email"],
        "email_verified": ["email_verified"],
        "id": ["sub", "userid"],
        "iss": ["iss"],
        "aud": ["aud"],
    }

@pytest.fixture
def userinfo_common():
    return {
        "sub": "abc-123",
        "name": "User One",
        "email": "u1@example.org",
        "iss": "https://issuer.example.org",
        "aud": "client-123",
    }

def test_load_claim_map_reads_file(tmp_path):
    cfg = {"email": ["email"], "roles": ["roles"]}
    p = tmp_path / "claim_map.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")

    loaded = load_claim_map(str(p))
    assert loaded == cfg

def test_load_claim_map_nonexistent_returns_empty(tmp_path):
    p = tmp_path / "missing.json"
    assert load_claim_map(str(p)) == {}

def test_load_claim_map_falsy_returns_empty():
    assert load_claim_map("") == {}

def test_resolve_direct_string_key(userinfo_common, base_claim_map):
    ui = dict(userinfo_common, **{"email": "u1@example.org"})
    assert resolve_claim(ui, base_claim_map, "email") == "u1@example.org"

def test_resolve_default_when_missing(userinfo_common, base_claim_map):
    assert resolve_claim(userinfo_common, base_claim_map, "email_verified", default="unknown") == "unknown"

def test_first_non_empty_wins(userinfo_common, base_claim_map):
    # roles exists at top level -> should not evaluate later candidates
    ui = dict(userinfo_common, **{
        "roles": ["r1"],
        "realm_access": {"roles": ["r2"]},
        "resource_access": {"api": {"roles": ["r3"]}},
    })
    assert resolve_claim(ui, base_claim_map, "roles", default=[]) == ["r1"]

def test_non_empty_filter_skips_empty_list(userinfo_common, base_claim_map):
    # groups exists but empty; second candidate is namespaced and present -> should pick second
    ui = dict(userinfo_common, **{
        "groups": [],
        "https://example.com/groups": ["gA", "gB"],
    })
    assert resolve_claim(ui, base_claim_map, "groups", default=[]) == ["gA", "gB"]

def test_namespaced_exact_key(userinfo_common, base_claim_map):
    ui = dict(userinfo_common, **{
        "https://example.com/roles": ["rA", "rB"]
    })
    # If the exact namespaced key is present, it should be found when configured
    # Here base_claim_map doesn't include the exact domain by default; emulate an override:
    claim_map = dict(base_claim_map)
    claim_map["roles"] = ["https://example.com/roles", "roles"]
    assert resolve_claim(ui, claim_map, "roles", default=[]) == ["rA", "rB"]

def test_namespaced_wildcard_key(userinfo_common, base_claim_map):
    ui = dict(userinfo_common, **{
        "https://tenant.example.com/groups": ["g1", "g2"]
    })
    # base map includes "https://*/groups" -> should match
    assert resolve_claim(ui, base_claim_map, "groups", default=[]) == ["g1", "g2"]

def test_literal_dots_in_key(userinfo_common, base_claim_map):
    # Ensure dots in a string key are treated literally (no splitting)
    ui = dict(userinfo_common, **{"a.b": "value"})
    claim_map = {"custom": ["a.b"]}
    assert resolve_claim(ui, claim_map, "custom") == "value"

def test_list_path_two_levels(userinfo_common, base_claim_map):
    ui = dict(userinfo_common, **{"realm_access": {"roles": ["r1","r2"]}})
    assert resolve_claim(ui, base_claim_map, "roles", default=[]) == ["r1", "r2"]

def test_wildcard_over_dict_values_flatten(userinfo_common, base_claim_map):
    # resource_access.*.roles -> flatten lists from multiple clients
    ui = dict(userinfo_common, **{
        "resource_access": {
            "api": {"roles": ["apiRole"]},
            "svc": {"roles": ["svcRole1", "svcRole2"]},
        }
    })
    out = resolve_claim(ui, base_claim_map, "roles", default=[])
    assert sorted(out) == ["apiRole", "svcRole1", "svcRole2"]

def test_segment_level_wildcard_pattern(userinfo_common, base_claim_map):
    # Use an explicit wildcard at the middle segment (e.g., "svc*")
    ui = dict(userinfo_common, **{
        "resource_access": {
            "svc-api": {"roles": ["a"]},
            "svc-web": {"roles": ["b"]},
            "other":   {"roles": ["c"]},
        }
    })
    claim_map = dict(base_claim_map)
    claim_map["roles"] = [
        ["resource_access", "svc*", "roles"],  # this should match svc-api and svc-web only
    ]
    out = resolve_claim(ui, claim_map, "roles", default=[])
    # Because we used an explicit wildcard segment (not None), this is not a flatten; it returns first match.
    # Our implementation returns the FIRST matching key's value (iteration order of dict).
    # To make this deterministic, assert it returns a list from one of the svc-* entries.
    assert out in (["a"], ["b"])

def test_list_encounter_stops_and_tries_next_path(userinfo_common, base_claim_map):
    # If a segment expects a dict but finds a list, resolution returns None and we try the next candidate
    ui = dict(userinfo_common, **{
        "realm_access": ["not-a-dict"],   # breaks second roles path
        "roles": ["topR"]
    })
    assert resolve_claim(ui, base_claim_map, "roles", default=[]) == ["topR"]

def test_missing_everywhere_returns_default(userinfo_common, base_claim_map):
    assert resolve_claim(userinfo_common, base_claim_map, "groups", default=[]) == []

def test_empty_string_is_treated_as_empty(userinfo_common, base_claim_map):
    ui = dict(userinfo_common, **{"preferred_username": ""})
    # preferred_username path falls back to username -> name
    ui["name"] = "Fallback Name"
    assert resolve_claim(ui, base_claim_map, "preferred_username") == "Fallback Name"
