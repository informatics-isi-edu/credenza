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
import time
import base64
import logging
import requests
from datetime import datetime, timezone
from requests.adapters import HTTPAdapter
from typing import Iterable, Optional, Set, Tuple, List, Dict, Union
from flask import current_app, request, abort
from urllib3.util import Retry
from urllib.parse import urlparse
from requests import HTTPError, Timeout, ConnectionError
from ..session.storage.session_store import SessionData
from ...telemetry import audit_event

logger = logging.getLogger(__name__)

MAX_RESOURCES = 32
MAX_SCOPES = 32


def extract_session_key() -> Tuple[str, bool]:
    auth = request.headers.get("Authorization")
    if auth and auth[:7].lower() == "bearer ":
        return auth[7:], True
    cookie_val = request.cookies.get(current_app.config["COOKIE_NAME"])
    return cookie_val, False


def get_current_session(dont_abort:bool = False) -> Tuple[Optional[str], Optional[SessionData]]:
    skey, is_bearer_token = extract_session_key()
    if not skey:
        logger.debug(f"No session key found in request")
        return (None, None) if dont_abort else abort(404)

    store = current_app.config["SESSION_STORE"]
    sid, session = store.get_active_session_by_session_key(skey)
    if sid and session:
        return sid, session

    provider = get_augmentation_provider(get_realm())
    if (current_app.config.get("ENABLE_LEGACY_API", False) and
        hasattr(provider, "session_from_bearer_token") and is_bearer_token):
        skey, session = provider.session_from_bearer_token(skey)
        sid, session =  store.get_active_session_by_session_key(skey)

    if sid and session:
        return sid, session

    logger.debug(f"No active session found for {skey[:8]}...")
    return (None, None) if dont_abort else abort(404)


def get_realm(realm=None) -> str:
    if realm and realm in current_app.config["OIDC_IDP_PROFILES"].keys():
        return realm
    default = current_app.config.get("DEFAULT_REALM")
    if not default:
        abort(400, "No valid realm provided and no DEFAULT_REALM configured")
    return default


def get_augmentation_provider(realm=None):
    if realm is None:
        realm = get_realm()
    providers = current_app.config["SESSION_AUGMENTATION_PROVIDERS"]
    provider = providers.get(realm)
    return provider


def get_augmentation_provider_params(realm=None):
    profile = current_app.config["OIDC_IDP_PROFILES"].get(get_realm(realm), {})
    return profile.get("session_augmentation_params", {})


def augment_session(tokens, realm, userinfo, metadata):
    provider = get_augmentation_provider(realm)
    provider_params = get_augmentation_provider_params(realm)
    defer_augmentation = provider_params.get("defer_augmentation", False)
    if defer_augmentation and not metadata.get("augmentation_deferred", False):
        metadata.update({"augmentation_deferred": defer_augmentation})
        return userinfo, {}

    # look for additional tokens in the response
    additional_tokens = provider.process_additional_tokens(tokens, int(time.time()))
    # possibly get additional groups using external tokens or other means
    provider.enrich_userinfo(userinfo, additional_tokens)
    return userinfo, additional_tokens


def get_effective_scopes(session: SessionData) -> list:
    if not session:
        return []
    effective_scopes = list(session.scopes.split()) if session.scopes else []
    additional_scopes = list(session.additional_tokens.keys())
    effective_scopes.extend(additional_scopes)
    return effective_scopes


def get_tokens_by_scope(session: SessionData) -> dict:
    tokens = {session.scopes: {"access_token": session.access_token, "refresh_token": session.refresh_token}}
    for k, v in session.additional_tokens.items():
        tokens[k] = {"access_token": v["access_token"], "refresh_token": v.get("refresh_token")}

    return tokens


def refresh_access_token(sid, session):
    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(session.realm, native_client=session.is_device())
    updated = False

    now = int(time.time())
    token_expires_at = session.session_metadata.system.get("access_token_expires_at")
    absolute_expires_at = session.absolute_expires_at
    # Refresh access token only when the token is expired or about to expire
    if (token_expires_at and
            token_expires_at < now + current_app.config.get("TOKEN_EXPIRY_THRESHOLD", 300) and
            absolute_expires_at and absolute_expires_at > now):

        try:
            refreshed = client.refresh_access_token(refresh_token=session.refresh_token)
        except Exception as e:
            logger.warning(
                f"Access token refresh failed for session {sid} for user {user} {sub} on realm {realm}: {e}")
            audit_event("access_token_refresh_failed",
                        session_id=sid, user=user, sub=sub, realm=realm, error=str(e))
            return updated

        # update tokens and metadata
        session.access_token = refreshed["access_token"]
        session.refresh_token = refreshed.get("refresh_token", session.refresh_token)
        session.id_token = refreshed.get("id_token", session.id_token)
        session.session_metadata.system["access_token_expires_at"] = refreshed["expires_at"]
        if "refresh_expires_in" in refreshed:
            session.absolute_expires_at = now + refreshed["refresh_expires_in"]
            session.session_metadata.system["refresh_token_expires_at"] = session.absolute_expires_at

        logger.debug(f"Access token refresh for session {sid} for user {user} ({sub}) on realm {realm} complete")
        audit_event("access_token_refreshed", session_id=sid, user=user, sub=sub, realm=realm)
        updated = True

    return updated


def refresh_additional_tokens(sid, session):
    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    tokens = session.additional_tokens or {}
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(session.realm, native_client=session.is_device())

    updated = False
    for scope, token in list(tokens.items()):
        refresh_token = token.get("refresh_token")
        if not refresh_token:
            # logger.debug(f"Token for scope '{scope}' does not contain a refresh token and cannot be refreshed")
            continue

        now = int(time.time())
        expires_at = token.get("expires_at", 0)
        expiry_threshold = current_app.config.get("TOKEN_EXPIRY_THRESHOLD", 300)
        if now < expires_at - expiry_threshold:
            # current_time_dt = datetime.fromtimestamp(now).isoformat()
            # expires_at_threshold_dt = datetime.fromtimestamp(expires_at - expiry_threshold).isoformat()
            # logger.debug(f"Additional token refresh skipped for [sid={sid}, user={user}, sub={sub}, scope={scope}] "
            #              f"with current time {current_time_dt} not exceeding expiry threshold {expires_at_threshold_dt}")
            continue

        try:
            refreshed = client.refresh_access_token(refresh_token)
            logger.debug(f"Additional token refresh successful for sid={sid}, user={user}, sub={sub}, scope={scope}")
        except Exception as e:
            tokens.pop(scope, None)
            logger.warning(f"Token refresh failed for scope={scope}: {e}")
            audit_event("additional_token_refresh_failed",
                        sid=sid, user=user, sub=sub, scope=scope, realm=realm, error=str(e))
            continue

        tokens[scope].update({
            "access_token": refreshed["access_token"],
            "refresh_token": refreshed["refresh_token"],
            "expires_at": refreshed["expires_at"],
            "last_refresh_at": now,
            "refreshed_count": token.get("refreshed_count", 0) + 1
        })
        updated = True

        audit_event("additional_token_refresh_success",
                    sid=sid,
                    user=user,
                    sub=sub,
                    scope=scope,
                    expires_at=datetime.fromtimestamp(refreshed["expires_at"], timezone.utc).isoformat())
    session.additional_tokens = tokens

    return updated


def revoke_tokens(sid, session):
    if session.is_service():
        return

    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(realm, native_client=session.is_device())
    try:
        # try to revoke all tokens associated with the session
        tokens = get_tokens_by_scope(session)
        scopes = ' '.join(tokens.keys())
        logger.debug(f"Revoking access tokens and refresh tokens (if present) for scopes: [{scopes}]")
        for k, v in tokens.items():
            client.revoke_token(k, v["access_token"], token_type_hint="access_token")
            audit_event("access_token_revoked", sid=sid, user=user, sub=sub, realm=realm, scope=k)
            refresh_token = v.get("refresh_token")
            if refresh_token:
                client.revoke_token(k, refresh_token, token_type_hint="refresh_token")
                audit_event("refresh_token_revoked", sid=sid, user=user, sub=sub, realm=realm, scope=k)
    except Exception as e:
        logger.warning(f"Exception during token revocation: {e}")


def parse_basic_auth(header_value: str) -> Optional[Dict[str, str]]:
    """
    Parse 'Authorization: Basic base64(client_id:client_secret)'.
    Returns dict {'client_id': ..., 'client_secret': ...} or None on parse failure.
    """
    if not header_value:
        return None
    parts = header_value.split(None, 1)
    if len(parts) != 2:
        return None
    scheme, b64 = parts
    if scheme.lower() != "basic":
        return None
    try:
        value = base64.b64decode(b64.strip()).decode("utf-8")
    except Exception:
        return None
    if ":" not in value:
        return None
    cid, secret = value.split(":", 1)
    return {"client_id": cid, "client_secret": secret}


def get_request_resource_args(resources: list, maxsize: int = MAX_RESOURCES):
    result = normalize_str_list(resources)

    if not result and current_app.config.get("ENABLE_LEGACY_API", False):
        default_res = current_app.config.get("LEGACY_DEFAULT_RESOURCE")
        return [default_res] if default_res else []

    return result[:maxsize] if isinstance(maxsize, int) else result


def validate_resource_string(value: str) -> str:
    """
    Validate a resource identifier.

    Rules:
      - Accept 'urn:...' values verbatim.
      - Otherwise require a full URI with scheme and host.
      - Disallow userinfo in netloc (no user:pass@host).
      - Require https scheme for network URIs, except permit http for
        'localhost' and '127.0.0.1' to allow local development.
    Returns the cleaned string on success, otherwise raises ValueError.
    """
    if value is None:
        raise ValueError("resource value required")

    v = str(value).strip()
    if v == "":
        raise ValueError("empty resource value not allowed")

    if v.lower().startswith("urn:"):
        return v

    p = urlparse(v)
    if not p.scheme or not p.netloc:
        raise ValueError("resource must be an urn or a full URI (scheme and host required)")

    # disallow userinfo (user:pass@host)
    if "@" in p.netloc:
        raise ValueError("resource must not contain userinfo")

    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()

    if scheme == "https":
        return v

    # permit http only for localhost/127.0.0.1
    if scheme == "http" and host in ("localhost", "127.0.0.1"):
        return v

    raise ValueError("network resource URIs must use https (http allowed only for localhost/127.0.0.1)")


def normalize_str_list(src: Optional[List[str]]) -> List[str]:
    """Normalize a list of strings: drop None, strip, lowercase if needed, dedupe and sort."""
    if not src:
        return []
    out: List[str] = []
    for v in src:
        if v is None:
            continue
        if not isinstance(v, str):
            raise ValueError("expected string elements in list")
        s = v.strip()
        if s == "":
            continue
        out.append(s)
    # dedupe while preserving deterministic order -> sort
    return sorted(set(out))


def collapse_str_list(src: Optional[List[str]]) -> Union[str, List[str]]:
    """
    Normalize a list of strings and collapse singleton lists.

    Behavior:
      - None or empty input -> []
      - One unique non-empty string -> that string
      - Multiple unique non-empty strings -> sorted list of strings

    Uses normalize_str_list() for trimming, deduping, sorting.
    """
    normalized = normalize_str_list(src)
    if len(normalized) == 1:
        return normalized[0]
    return normalized


# copied (and modded) from distutils so we don't have to depend on it
def strtobool (val):  # pragma: no cover
    """Convert a string representation of truth to bool True or False.

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return True
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return False
    else:
        raise ValueError("invalid truth value %r" % (val,))

def enrich_userinfo_from_endpoint(
    client,
    access_token: str,
    userinfo: dict,
    fallback_claims: list,
    realm: str,
    sub: str,
) -> dict:
    """Fill missing identity claims by calling the IDP userinfo endpoint.

    Called when the ID token is missing one or more claims listed in
    fallback_claims. ID token claims take precedence -- only absent or empty
    claims are filled from the endpoint response.

    On endpoint failure, or if required claims remain missing after the merge,
    emits an audit warning and returns the session in degraded form. Never
    aborts the login.

    Args:
        client: OIDCClient for the realm.
        access_token: Access token from the IDP token exchange.
        userinfo: Claims dict from the validated ID token (mutated in place).
        fallback_claims: Claim names that must be present (raw JWT claim names).
        realm: Realm name (for audit events).
        sub: Subject identifier (for audit events).

    Returns:
        Enriched userinfo dict.
    """
    missing_before = [c for c in fallback_claims if not userinfo.get(c)]

    try:
        endpoint_data = client.fetch_userinfo(access_token)
    except Exception as exc:
        logger.warning(
            "userinfo fallback failed for realm=%s sub=%s missing=%s: %s",
            realm, sub, missing_before, exc,
        )
        audit_event(
            "userinfo_fallback_failed",
            realm=realm,
            sub=sub,
            missing_claims=missing_before,
            error=str(exc),
        )
        return userinfo

    filled = []
    for k, v in endpoint_data.items():
        if not userinfo.get(k):
            userinfo[k] = v
            filled.append(k)

    logger.debug(
        "userinfo fallback merged claims for realm=%s sub=%s filled=%s",
        realm, sub, filled,
    )

    missing_after = [c for c in fallback_claims if not userinfo.get(c)]
    if missing_after:
        logger.warning(
            "userinfo fallback incomplete for realm=%s sub=%s still_missing=%s",
            realm, sub, missing_after,
        )
        audit_event(
            "userinfo_fallback_incomplete",
            realm=realm,
            sub=sub,
            missing_claims=missing_after,
        )
    else:
        logger.info(
            "userinfo fallback filled claims for realm=%s sub=%s filled=%s",
            realm, sub, missing_before,
        )
        audit_event(
            "userinfo_fallback_filled",
            realm=realm,
            sub=sub,
            filled_claims=filled,
        )

    return userinfo


# Key claims expected when each standard OIDC scope is requested.
# Optional profile fields (birthdate, picture, website, etc.) are excluded to
# avoid spurious userinfo calls for IDPs that do not populate them.
_SCOPE_EXPECTED_CLAIMS = {
    "email":   ["email"],
    "profile": ["name", "preferred_username"],
}


def get_missing_scope_claims(
    scopes_str: str,
    userinfo: dict,
    scope_expected_claims: Optional[dict] = None,
) -> list:
    """Return key claims expected from scopes_str that are absent in userinfo.

    Used to decide whether a userinfo endpoint call is warranted after ID token
    validation. Only checks the claims listed in _SCOPE_EXPECTED_CLAIMS; unknown
    or IDP-internal scopes (URN scopes, resource URI scopes) are silently skipped.

    scope_expected_claims is shallow-merged over the global defaults: only the
    scopes it declares are affected, all others retain their global defaults.
    This lets an IDP profile override or extend a single scope's expected claims
    (or add a custom scope) without redeclaring the rest.
    """
    effective = _SCOPE_EXPECTED_CLAIMS if not scope_expected_claims \
        else {**_SCOPE_EXPECTED_CLAIMS, **scope_expected_claims}
    missing = []
    seen: set = set()
    for scope in scopes_str.split():
        for claim in effective.get(scope, []):
            if claim not in seen and not userinfo.get(claim):
                missing.append(claim)
                seen.add(claim)
    return missing


def check_client_scope_coverage(
    issuable_scopes: list,
    clients: dict,
) -> list:
    """Check that each client's allowed_scopes are covered by issuable_scopes.

    Returns a list of warning strings and also emits each via logger.warning.
    Only called when the IDP profile explicitly declares issuable_scopes.
    """
    issuable_set = set(issuable_scopes)
    warnings = []
    for client_id, client_rec in clients.items():
        for scope in (client_rec.allowed_scopes or []):
            if scope not in issuable_set:
                msg = (
                    f"Client {client_id}: allowed_scope {scope!r} is not in issuable_scopes "
                    f"and may not be deliverable to clients"
                )
                logger.warning(msg)
                warnings.append(msg)
    return warnings


def is_transient_request_error(e): # pragma: no cover
    if isinstance(e, (Timeout, ConnectionError)):
        return True
    if isinstance(e, HTTPError) and getattr(e, "response", None):
        return 500 <= e.response.status_code < 600
    return False

def safe_referrer(url: str) -> str:# pragma: no cover
    if not url: return "/"
    p = urlparse(url)
    if p.scheme or p.netloc:  # absolute/externals -> reject
        if not current_app.config.get("ENABLE_LEGACY_API", False):  # TODO: remove this, eventually
            return "/"
    # prevent '//' which can be treated as scheme-relative
    if url.startswith("//"):
        return "/"
    return url

def retrying_requests_session(
    *,
    total: int = 3,
    connect: Optional[int] = None,   # defaults to 'total' if None
    read: Optional[int] = None,
    status: Optional[int] = None,
    backoff_factor: float = 0.3,     # ~0.3, 0.6, 1.2s between attempts (exp)
    status_forcelist: Iterable[int] = (500, 502, 503, 504),
    allowed_methods: Optional[Set[str]] = frozenset({"GET"}),
    pool_connections: int = 16,
    pool_maxsize: int = 16) -> requests.Session:
    """
    Build a requests.Session configured to retry on transient errors.
    - Retries: connect/read failures and the given 5xx codes.
    - Never retries 4xx (e.g., SignatureDoesNotMatch).
    - Honors Retry-After headers.
    """
    retry = Retry(
        total=total,
        connect=connect if connect is not None else total,
        read=read if read is not None else total,
        status=status if status is not None else total,
        status_forcelist=set(status_forcelist),
        allowed_methods=allowed_methods,   # None => retry on any; we restrict to GET
        backoff_factor=backoff_factor,
        respect_retry_after_header=True,
        raise_on_redirect=False,
        raise_on_status=False,             # we'll inspect status ourselves
    )
    adapter = HTTPAdapter(max_retries=retry,
                          pool_connections=pool_connections,
                          pool_maxsize=pool_maxsize)
    s = requests.Session()
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s
