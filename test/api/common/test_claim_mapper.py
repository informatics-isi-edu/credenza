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
from copy import deepcopy
from credenza.api.common.claim_mapper import (
    DEFAULT_CLAIM_MAP,
    ClaimMap,
    build_realm_claim_maps,
    get_claim_map_for_realm,
    resolve_claim,
    merge_additional_claims
)

def test_build_maps_applies_preset_on_exact_realm_name():
    profiles = {
        "cognito": {
            "client_id": "web",
        }
    }
    realm_maps = build_realm_claim_maps(profiles)
    assert "cognito" in realm_maps
    assert realm_maps["cognito"]["groups"][1] == "cognito:groups"
    assert "default" in realm_maps

def test_build_maps_applies_preset_on_substring_match():
    profiles = {
        "keycloak-local": {
            "client_id": "web",
        }
    }
    realm_maps = build_realm_claim_maps(profiles)
    roles_paths = realm_maps["keycloak-local"]["roles"]
    # keycloak preset puts realm_access.roles ahead of plain roles
    assert roles_paths[0] == ["realm_access", "roles"]

def test_substring_choice_prefers_longest_match_when_multiple():
    # Artificial preset collision scenario: if you ever added overlapping names, longest wins.
    # For current presets this is mostly a safety net; we emulate by adding a temp preset.
    try:
        from credenza.api.common import claim_mapper as cm
        cm.IDP_PRESETS["kc"] = {"roles": [["realm_access", "roles"]]}
        profiles = {"my-kc-keycloak": {}}
        realm_maps = cm.build_realm_claim_maps(profiles)
        roles_paths = realm_maps["my-kc-keycloak"]["roles"]
        # "keycloak" (longer) should be chosen over "kc"
        assert roles_paths[0] == ["realm_access", "roles"]
    finally:
        # cleanup
        if "kc" in cm.IDP_PRESETS:
            del cm.IDP_PRESETS["kc"]

def test_build_maps_overrides_replace_roles_list():
    profiles = {
        "keycloak": {
            "claim_map_overrides": {
                "roles": [["resource_access", "my-client", "roles"]]
            }
        }
    }
    realm_maps = build_realm_claim_maps(profiles)
    assert realm_maps["keycloak"]["roles"] == [["resource_access", "my-client", "roles"]]

def test_build_maps_default_when_missing_profiles():
    realm_maps = build_realm_claim_maps({})
    assert "default" in realm_maps
    assert realm_maps["default"] == DEFAULT_CLAIM_MAP

def test_get_claim_map_for_realm_fallback_to_default():
    realm_maps = {"default": DEFAULT_CLAIM_MAP, "r1": {"email": ["email"]}}
    assert get_claim_map_for_realm("r1", realm_maps)["email"] == ["email"]
    assert get_claim_map_for_realm("missing", realm_maps) == DEFAULT_CLAIM_MAP
    assert get_claim_map_for_realm(None, realm_maps) == DEFAULT_CLAIM_MAP

def test_realm_overrides_take_precedence_over_preset_and_defaults():
    profiles = {
        "auth0-tenantA": {  # substring should match "auth0" preset (which may be empty), then override wins
            "claim_map_overrides": {
                "groups": ["https://tenant.example.com/groups"]
            }
        }
    }
    realm_maps = build_realm_claim_maps(profiles)
    cmap = realm_maps["auth0-tenantA"]
    ui = {"https://tenant.example.com/groups": ["g1"]}
    assert resolve_claim(ui, cmap, "groups", [], listify=True) == ["g1"]

def test_resolve_direct_key_and_list_path():
    cm = deepcopy(DEFAULT_CLAIM_MAP)
    ui = {
        "email": "e@example.org",
        "realm_access": {"roles": ["r1", "r2"]},
    }
    # direct key
    assert resolve_claim(ui, cm, "email") == "e@example.org"
    # list path (second candidate for roles)
    assert resolve_claim(ui, cm, "roles", default=[], listify=True) == ["r1", "r2"]

def test_resolve_order_first_match_wins():
    cm = {
        "preferred_username": ["preferred_username", "username", "name"],
    }
    ui = {"username": "u1", "name": "Name"}
    # preferred_username missing -> falls to username
    assert resolve_claim(ui, cm, "preferred_username") == "u1"

def test_resolve_listify_wraps_scalar_and_keeps_lists():
    cm = {"groups": ["groups"]}
    assert resolve_claim({"groups": "dev"}, cm, "groups", [], listify=True) == ["dev"]
    assert resolve_claim({"groups": ["dev", "ops"]}, cm, "groups", [], listify=True) == ["dev", "ops"]

def test_resolve_default_on_missing_or_empty():
    cm = {"groups": ["groups"], "email": ["email"]}
    assert resolve_claim({}, cm, "groups", default=[]) == []
    assert resolve_claim({"email": ""}, cm, "email", default="unknown") == "unknown"

def test_preset_effect_in_resolution_with_substring_realm_name():
    profiles = {
        "cognito-dev": {  # substring should apply the 'cognito' preset
            "client_id": "web"
        }
    }
    realm_maps = build_realm_claim_maps(profiles)
    cmap = realm_maps["cognito-dev"]
    ui = {"cognito:groups": ["A", "B"]}
    assert resolve_claim(ui, cmap, "groups", [], listify=True) == ["A", "B"]

def test_merge_additional_claims_normalizes_and_respects_allowed():
    userinfo = {"email": "e@x.com"}
    # adapter supplies a flat key "username" which should map -> "preferred_username"
    additional = {"username": "u1", "roles": ["r1"]}
    claim_map = DEFAULT_CLAIM_MAP

    # allow only preferred_username (so roles should be rejected)
    merged, changes = merge_additional_claims(userinfo,
                                              additional,
                                              claim_map=claim_map,
                                              allowed_claims={"preferred_username"})
    assert merged["preferred_username"] == "u1"
    assert "roles" in changes and changes["roles"]["action"] == "skipped_disallowed"

def test_merge_additional_claims_skips_non_json_safe_values():
    userinfo = {}
    # object() is not JSON-safe
    additional = {"weird": object()}
    # put "weird" in a claim_map entry so normalization doesn't change the key
    claim_map = {"weird": ["weird"]}

    merged, changes = merge_additional_claims(userinfo, additional, claim_map=claim_map)
    assert "weird" not in merged
    assert "weird" in changes and changes["weird"]["action"] == "skipped_non_json_safe"

def test_merge_additional_claims_overwrite_and_skip_existing_behaviour():
    userinfo = {"email": "old@example.org"}
    additional = {"email": "new@example.org"}
    claim_map = {"email": ["email"]}

    # default: overwrite=False -> skip existing
    merged1, changes1 = merge_additional_claims(userinfo, additional, claim_map=claim_map, overwrite=False)
    assert merged1["email"] == "old@example.org"
    assert changes1["email"]["action"] == "skipped_existing"

    # with overwrite=True -> replace
    merged2, changes2 = merge_additional_claims(userinfo, additional, claim_map=claim_map, overwrite=True)
    assert merged2["email"] == "new@example.org"
    assert changes2["email"]["action"] == "overwrite"
    assert changes2["email"]["prev"] == "old@example.org"

def test_merge_additional_claims_listify_keys_coerces_scalar_to_list():
    userinfo = {}
    additional = {"groups": "dev"}
    claim_map = {"groups": ["groups"]}

    merged, changes = merge_additional_claims(userinfo, additional, claim_map=claim_map, listify_keys={"groups"})
    assert merged["groups"] == ["dev"]
    assert changes["groups"]["action"] == "add"

def test_resolve_claim_prefers_canonical_then_fallback():

    # claim_map that prefers 'name' as the source for full_name
    cm: ClaimMap = {"full_name": ["name"], "email": ["email"]}

    # Case A: canonical key present (e.g., after early normalization)
    ui_a = {"full_name": "Canonical Name"}
    assert resolve_claim(ui_a, cm, "full_name", default=None) == "Canonical Name"

    # Case B: canonical missing but source path present
    ui_b = {"name": "Adapter Name"}
    assert resolve_claim(ui_b, cm, "full_name", default=None) == "Adapter Name"

    # listify behavior: scalar -> list if requested
    ui_c = {"full_name": "Single"}
    assert resolve_claim(ui_c, cm, "full_name", default=None, listify=True) == ["Single"]
