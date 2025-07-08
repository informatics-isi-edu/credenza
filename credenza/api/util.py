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
import json
import time
import base64
import logging
import ipaddress
from typing import Optional
from datetime import datetime
from zoneinfo import ZoneInfo
from tzlocal import get_localzone_name
from publicsuffix2 import get_sld
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from flask import current_app, request, Response, abort
from .session.storage.session_store import SessionData
from ..telemetry import audit_event


logger = logging.getLogger(__name__)


class AESGCMCodec:
    def __init__(self, key: str):
        if key is None:
            raise ValueError("Key is required")
        key_bytes = key.encode()
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError(f"Key must be a 16, 24, or 32-byte UTF-8 string. Key length: {len(key_bytes)}")
        self.key = key_bytes

    def encrypt(self, plaintext: str) -> str:
        try:
            nonce = get_random_bytes(12)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

            data = {
                "nonce": base64.urlsafe_b64encode(nonce).decode(),
                "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
                "tag": base64.urlsafe_b64encode(tag).decode()
            }
            return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt(self, ciphertext: str) -> Optional[str]:
        try:
            data_json = base64.urlsafe_b64decode(ciphertext.encode()).decode()
            data = json.loads(data_json)

            nonce = base64.urlsafe_b64decode(data["nonce"])
            ciphertext = base64.urlsafe_b64decode(data["ciphertext"])
            tag = base64.urlsafe_b64decode(data["tag"])

            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None


def extract_session_key() -> (str, bool):
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        return auth.split(" ", 1)[1], True
    cookie_val = request.cookies.get(current_app.config["COOKIE_NAME"])
    return cookie_val, False


def has_current_session() -> str or None:
    skey,_ = extract_session_key()
    if not skey:
        return None

    store = current_app.config["SESSION_STORE"]
    sid, session = store.get_session_by_session_key(skey)
    if not session:
        return None

    return sid


def get_current_session() -> (str, SessionData):
    skey, is_bearer_token = extract_session_key()
    if not skey:
        abort(404)

    store = current_app.config["SESSION_STORE"]
    sid, session = store.get_session_by_session_key(skey)
    if sid and session:
        return sid, session

    provider = get_augmentation_provider(get_realm())
    if (current_app.config.get("ENABLE_LEGACY_API", False) and
        hasattr(provider, "session_from_bearer_token") and is_bearer_token):
        skey, session = provider.session_from_bearer_token(skey)
        return store.get_session_by_session_key(skey)
    else:
        abort(404)


def get_realm(realm=None) -> str:
    if realm and realm in current_app.config["OIDC_IDP_PROFILES"].keys():
        return realm
    default = current_app.config.get("DEFAULT_REALM")
    if not default:
        abort(400, "No valid realm provided and no DEFAULT_REALM configured")
    return default


def get_augmentation_provider(realm=None):
    providers = current_app.config["SESSION_AUGMENTATION_PROVIDERS"]
    provider = providers.get(realm, providers["default"])
    logger.debug(f"Using augmentation provider {provider} for realm {realm}")
    return provider


def generate_nonce():
  nonce = str(time.time()) + '.' + base64.urlsafe_b64encode(get_random_bytes(30)).decode() + '.'
  return nonce


def make_json_response(data):
    return Response(
        json.dumps(data, sort_keys=False),  # Preserve key order
        mimetype="application/json"
    )


def get_effective_scopes(session: SessionData) -> list:
    if not session:
        return []
    effective_scopes = list(session.scopes.split())
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
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(session.realm)
    updated = False

    now = time.time()
    token_expires_at = session.session_metadata.system.get("token_expires_at")
    refresh_expires_at = session.session_metadata.system.get("refresh_expires_at")

    # Refresh access token only when the token is expired or about to expire
    if (token_expires_at and
            token_expires_at < now + current_app.config.get("TOKEN_EXPIRY_THRESHOLD", 300) and
            refresh_expires_at and
            refresh_expires_at > now):

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
        session.session_metadata.system["token_expires_at"] = refreshed["expires_at"]
        if "refresh_expires_at" in refreshed:
            session.session_metadata.system["refresh_expires_at"] = \
                refreshed["refresh_expires_at"]

        logger.debug(f"Access token refresh for session {sid} for user {user} ({sub}) on realm {realm} complete")
        audit_event("access_token_refreshed", session_id=sid, user=user, sub=sub, realm=realm)
        updated = True

    return updated


def refresh_additional_tokens(sid, session):
    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    tokens = session.additional_tokens or {}
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(session.realm)

    updated = False
    for scope, token in list(tokens.items()):
        refresh_token = token.get("refresh_token")
        if not refresh_token:
            # logger.debug(f"Token for scope '{scope}' does not contain a refresh token and cannot be refreshed")
            continue

        now = time.time()
        expires_at = token.get("expires_at", 0)
        expiry_threshold = current_app.config.get("TOKEN_EXPIRY_THRESHOLD", 300)
        if now < expires_at - expiry_threshold:
            # current_time_dt = datetime.fromtimestamp(now, tz=ZoneInfo(get_localzone_name())).isoformat()
            # expires_at_threshold_dt = datetime.fromtimestamp(expires_at - expiry_threshold,
            #                                                  tz=ZoneInfo(get_localzone_name())).isoformat()
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
                    expires_at=datetime.fromtimestamp(refreshed["expires_at"],
                                                      tz=ZoneInfo(get_localzone_name())).isoformat())
    session.additional_tokens = tokens

    return updated


def revoke_tokens(sid, session):
    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(realm)
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


def get_cookie_domain():
    """
    Determine which cookie domain to use, based on configuration.

    - If COOKIE_DOMAIN is unset or None: do not set a cookie domain (passthrough to set_cookie which will use FQHN).
    - If COOKIE_DOMAIN is 'true' or True: determine a base domain heuristically via publicsuffix2.get_sld().
    - If COOKIE_DOMAIN is a non-IP-address string (e.g. 'example.org'): use it as-is.

    Returns:
        str | None: The cookie domain to use, or None to omit the 'domain' attribute.
    """
    configured = current_app.config.get("COOKIE_DOMAIN")

    if configured and str(configured).lower() in ("true", "1", "yes"):
        host = request.host.split(":")[0]  # strip port

        # Rule out localhost or numeric IPs
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass

        if host.endswith("localhost"):
            return None

        base_domain = get_sld(host)
        return base_domain if base_domain else None

    if isinstance(configured, str) and configured.strip().lower() not in ("false", "none"):
        return configured.strip()

    return None


def is_browser_client(request): # pragma: no cover
    has_cookie = current_app.config["COOKIE_NAME"] in request.cookies
    accept_html = "text/html" in request.headers.get("Accept", "")
    ua = request.headers.get("User-Agent", "").lower()
    ua_looks_browser = any(x in ua for x in ["mozilla", "chrome", "safari", "edge", "firefox"])

    return has_cookie and (accept_html or ua_looks_browser)

# copied from distutils so we don't have to depend on it
def strtobool (val):  # pragma: no cover
    """Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return 1
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))