#
# Copyright 2026 University of Southern California
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
"""Configurable session attributes in the audit log (ADR-0012).

A realm's IdP profile may declare an "audit_attributes" list. Each entry selects values from one
userinfo claim (resolved through the realm claim map) into a deployment-named output field. The
selected values are written as a "session_attributes_updated" audit event when a session is
created and again whenever an upstream refresh changes them, so an investigator can tell which
permissions a session held at any point in its life. Credenza itself attaches no meaning to the
values.
"""
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from flask import current_app, has_app_context
from ...api.common.claim_mapper import DEFAULT_CLAIM_MAP, get_claim_map_for_realm, resolve_claim
from ...api.session.augmentation.base_provider import EnrichmentResult
from .logger import audit_event
from .identity import audit_identity

FIELD_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
GROUP_REFERENCE = re.compile(r"\\(\d+)|\\g<(\w+)>")
DEFAULT_MAX_VALUES = 100
MAX_VALUE_LEN = 256
SELECT_KEYS = ("id", "display_name")
ALLOWED_KEYS = {"field", "claim", "select", "match", "emit", "pii", "max_values"}

SelectedValues = Dict[str, List[str]]


@dataclass(frozen=True)
class AttributeSelector:
    field: str
    claim: str
    select: str = "id"
    match: Optional[re.Pattern] = None
    emit: Optional[str] = None
    pii: bool = False
    max_values: int = DEFAULT_MAX_VALUES


def parse_audit_attributes(spec, realm: str) -> List[AttributeSelector]:
    """Validate one realm's "audit_attributes" list and return its selectors.

    Raises ValueError on any malformed entry: a selector that is silently ignored would leave an
    audit gap nobody notices until an investigation needs it.
    """
    if spec is None:
        return []
    if not isinstance(spec, list):
        raise ValueError(f"audit_attributes for realm '{realm}' must be a list")

    selectors = []
    seen = set()
    for i, entry in enumerate(spec):
        where = f"audit_attributes[{i}] for realm '{realm}'"
        if not isinstance(entry, dict):
            raise ValueError(f"{where} must be an object")
        unknown = set(entry) - ALLOWED_KEYS
        if unknown:
            raise ValueError(f"{where} has unknown keys {sorted(unknown)}")

        field = entry.get("field")
        if not isinstance(field, str) or not FIELD_NAME.match(field):
            raise ValueError(f"{where} needs a 'field' matching {FIELD_NAME.pattern}")
        if field in seen:
            raise ValueError(f"{where} repeats field '{field}'")
        seen.add(field)

        claim = entry.get("claim")
        if not isinstance(claim, str) or not claim.strip():
            raise ValueError(f"{where} needs a non-empty 'claim'")

        select = entry.get("select", "id")
        if select not in SELECT_KEYS:
            raise ValueError(f"{where} 'select' must be one of {list(SELECT_KEYS)}")

        match = None
        if entry.get("match") is not None:
            try:
                match = re.compile(entry["match"])
            except (re.error, TypeError) as e:
                raise ValueError(f"{where} 'match' is not a valid regular expression: {e}") from e

        emit = entry.get("emit")
        if emit is not None:
            if match is None:
                raise ValueError(f"{where} 'emit' requires 'match'")
            if not isinstance(emit, str):
                raise ValueError(f"{where} 'emit' must be a string")
            for number, name in GROUP_REFERENCE.findall(emit):
                if number and int(number) > match.groups:
                    raise ValueError(f"{where} 'emit' references group {number}, "
                                     f"but 'match' has {match.groups}")
                if name and not (name.isdigit() and int(name) <= match.groups) \
                        and name not in match.groupindex:
                    raise ValueError(f"{where} 'emit' references unknown group '{name}'")

        pii = entry.get("pii", False)
        if not isinstance(pii, bool):
            raise ValueError(f"{where} 'pii' must be true or false")

        max_values = entry.get("max_values", DEFAULT_MAX_VALUES)
        if not isinstance(max_values, int) or isinstance(max_values, bool) or max_values < 1:
            raise ValueError(f"{where} 'max_values' must be a positive integer")

        selectors.append(AttributeSelector(field=field, claim=claim.strip(), select=select,
                                           match=match, emit=emit, pii=pii, max_values=max_values))
    return selectors


def build_realm_attribute_selectors(profiles: Optional[dict]) -> Dict[str, List[AttributeSelector]]:
    """Parse every realm's "audit_attributes"; realms without one are omitted."""
    selectors = {}
    for realm, profile in (profiles or {}).items():
        parsed = parse_audit_attributes((profile or {}).get("audit_attributes"), realm)
        if parsed:
            selectors[realm] = parsed
    return selectors


def _realm_selectors(realm) -> List[AttributeSelector]:
    if not has_app_context():
        return []
    return (current_app.config.get("AUDIT_ATTRIBUTE_SELECTORS") or {}).get(realm) or []


def _include_pii() -> bool:
    return bool(current_app.config.get("AUDIT_INCLUDE_PII", True)) if has_app_context() else True


def _claim_map(realm):
    realm_maps = current_app.config.get("IDP_CLAIM_MAPS") if has_app_context() else None
    return get_claim_map_for_realm(realm or "default", realm_maps or {}) or DEFAULT_CLAIM_MAP


def _select_one(selector: AttributeSelector, userinfo: dict, claim_map) -> Tuple[List[str], bool]:
    values = set()
    for item in resolve_claim(userinfo, claim_map, selector.claim, [], listify=True) or []:
        if isinstance(item, dict):
            item = item.get(selector.select)
        if not isinstance(item, str):
            continue
        if selector.match is not None:
            m = selector.match.fullmatch(item)
            if m is None:
                continue
            if selector.emit is not None:
                item = m.expand(selector.emit)
        values.add(item[:MAX_VALUE_LEN])
    ordered = sorted(values)
    return ordered[:selector.max_values], len(ordered) > selector.max_values


def select_session_attributes(userinfo: dict, realm) -> Tuple[SelectedValues, List[str]]:
    """Return ({field: sorted values}, [truncated fields]) for a realm's selectors."""
    selected, truncated = {}, []
    claim_map = _claim_map(realm)
    include_pii = _include_pii()
    for selector in _realm_selectors(realm):
        if selector.pii and not include_pii:
            continue
        values, cut = _select_one(selector, userinfo or {}, claim_map)
        selected[selector.field] = values
        if cut:
            truncated.append(selector.field)
    return selected, truncated


def _difference(after: SelectedValues, before: SelectedValues) -> SelectedValues:
    diff = {}
    for field, values in after.items():
        extra = sorted(set(values) - set(before.get(field, [])))
        if extra:
            diff[field] = extra
    return diff


def audit_session_attributes(session_id: str, userinfo: dict, realm, trigger: str,
                             enrichment: Optional[EnrichmentResult] = None,
                             before: Optional[SelectedValues] = None):
    """Write a session_attributes_updated event for a session whose augmentation just ran.

    trigger is "login", "device_login" or "refresh". enrichment is the provider's EnrichmentResult
    for the augmentation that just ran; its failed_sources become the event's complete /
    failed_sources (None means no augmentation result is available, treated as complete). On a
    refresh, pass the values selected before augmentation ran as `before`; the event is then
    written only if the selection changed or a source failed. At login the event is always
    written, even with an empty selection, because "held nothing" is worth recording. Realms
    without "audit_attributes" write nothing.
    """
    if not _realm_selectors(realm):
        return
    after, truncated = select_session_attributes(userinfo, realm)
    failures = list(enrichment.failed_sources) if enrichment is not None else []
    previous = before if before is not None else {}
    if before is not None and after == before and not failures:
        return

    audit_event("session_attributes_updated",
                session_id=session_id,
                **audit_identity(userinfo, realm),
                realm=realm,
                trigger=trigger,
                complete=not failures,
                attributes=after,
                added=_difference(after, previous),
                removed=_difference(previous, after),
                **({"failed_sources": failures} if failures else {}),
                **({"truncated": truncated} if truncated else {}))
