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
import uuid
import base64
import logging
import ipaddress
import requests
import functools
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from typing import Iterable, Optional, Set, Tuple
from datetime import datetime, timezone
from publicsuffix2 import get_sld
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from flask import current_app, request, make_response, Request, Response, abort, jsonify, g
from requests import HTTPError, Timeout, ConnectionError
from urllib.parse import urlparse
from ..common import client_ip
from ..session.storage.session_store import SessionData, SessionType
from ..auth.service.adapters.base import DEFAULT_MAX_ABSOLUTE_LIFETIME
from ...telemetry import audit_event


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


def extract_session_key() -> Tuple[str, bool]:
    auth = request.headers.get("Authorization")
    if auth and auth[:7].lower() == "bearer ":
        return auth[7:], True
    cookie_val = request.cookies.get(current_app.config["COOKIE_NAME"])
    return cookie_val, False


def has_current_session() -> Optional[str]:
    skey,_ = extract_session_key()
    if not skey:
        return None

    store = current_app.config["SESSION_STORE"]
    sid, session = store.get_session_by_session_key(skey)
    if not session:
        return None

    return sid


def get_current_session() -> Tuple[Optional[str], Optional[SessionData]]:
    skey, is_bearer_token = extract_session_key()
    if not skey:
        abort(404)

    store = current_app.config["SESSION_STORE"]
    sid, session = store.get_session_by_session_key(skey)
    if session and session.session_type == SessionType.service:
        policy = (session.session_metadata.system or {}).get("service_policy") or {}
        abs_life = int(policy.get("absolute_lifetime_seconds") or DEFAULT_MAX_ABSOLUTE_LIFETIME)
        # Absolute lifetime: never extend past created_at + abs_life
        if abs_life > 0:
            now = int(time.time())
            hard_stop = int(session.created_at) + abs_life
            if now >= hard_stop:
                store.delete_session(sid)
                audit_event(
                    "service_session_absolute_lifetime_exceeded",
                    session_id=sid,
                    realm=session.realm,
                    created_at=session.created_at,
                    absolute_lifetime_seconds=abs_life,
                )
                abort(401,
                      description=
                      f"Service session exceeded absolute lifetime")

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
    additional_tokens = provider.process_additional_tokens(tokens, time.time())
    # possibly get additional groups using external tokens or other means
    provider.enrich_userinfo(userinfo, additional_tokens)
    return userinfo, additional_tokens


def generate_nonce():
  nonce = str(time.time()) + '.' + base64.urlsafe_b64encode(get_random_bytes(30)).decode() + '.'
  return nonce


def make_json_response(data):
    return Response(
        json.dumps(data, sort_keys=False),  # Preserve key order
        mimetype="application/json"
    )


def route_label(req):
    # Prefer the matched rule (shows which alias hit), else fallback to raw path
    rule = getattr(req, "url_rule", None)
    route = rule.rule if rule is not None else req.path
    return f"{req.method} {route}"


def limit_or_429(limiter, key, detail):
    allowed, remaining, reset_s = limiter.allow(key)
    if allowed:
        return None, remaining, reset_s
    resp = make_response(jsonify({"error": "rate_limited", "detail": detail}), 429)
    resp.headers.update(limiter.headers(remaining, reset_s))
    resp.headers["Retry-After"] = str(reset_s)
    audit_event("request_rate_limited", detail=detail)
    return resp, remaining, reset_s


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
    sys_metadata = session.session_metadata.system or {}
    is_device_session = sys_metadata.get("device_session", False)
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(session.realm, native_client=is_device_session)
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
    sys_metadata = session.session_metadata.system or {}
    is_device_session = sys_metadata.get("device_session", False)
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(session.realm, native_client=is_device_session)

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
                    expires_at=datetime.fromtimestamp(refreshed["expires_at"], timezone.utc).isoformat())
    session.additional_tokens = tokens

    return updated


def revoke_tokens(sid, session):
    if session.session_type == SessionType.service:
        return
    sub = session.userinfo.get("sub")
    user = session.userinfo.get("email")
    realm = session.realm
    sys_metadata = session.session_metadata.system or {}
    is_device_session = sys_metadata.get("device_session", False)
    client = current_app.config["OIDC_CLIENT_FACTORY"].get_client(realm, native_client=is_device_session)
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
        Optional[str]: The cookie domain to use, or None to omit the 'domain' attribute.
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
        raise_on_status=False,             # we’ll inspect status ourselves
    )
    adapter = HTTPAdapter(max_retries=retry,
                          pool_connections=pool_connections,
                          pool_maxsize=pool_maxsize)
    s = requests.Session()
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

def get_correlation_id(req) -> str:
    # W3C Trace Context first
    tp = req.headers.get("traceparent")
    if tp:
        return tp  # or parse to extract trace-id

    # Common de-facto headers
    for h in ("X-Request-Id", "X-Request-ID", "x-request-id",
              "X-Correlation-Id", "X-Correlation-ID", "x-correlation-id",
              "X-Amzn-Trace-Id", "x-amzn-trace-id"):
        v = req.headers.get(h)
        if v:
            return v

    # Last resort: generate one and expose it
    rid = str(uuid.uuid4())

    return rid

def ip_rate_limited(unknown_bucket="10_per_min", normal_bucket="30_per_min"):
    """
    Decorator that enforces an IP-based rate limit and adds its headers
    to the final response. Stashes details in g.rate_limit for handlers.

    Set app.config["ENABLE_RATE_LIMITING"] = False to bypass entirely.

    Usage:
      @service_blueprint.route("/service/token", methods=["DELETE"])
      @ip_rate_limited()
      def revoke_service_token(): ...
    """
    def _decorator(fn):
        @functools.wraps(fn)
        def _wrapped(*args, **kwargs):
            # Bypass completely if disabled (default: enabled)
            try:
                enabled = current_app.config.get("ENABLE_RATE_LIMITING", True)
            except Exception:
                enabled = True

            if not enabled:
                return fn(*args, **kwargs)

            limits = current_app.extensions["rate_limits"]
            ip = client_ip(request)
            ip_key = f"ip:{ip}"
            detail = f"Too many requests: {route_label(request)} from: {ip_key}"
            bucket = limits[unknown_bucket] if ip == "unknown" else limits[normal_bucket]

            resp, rem, reset = limit_or_429(bucket, ip_key, detail)
            if resp is not None:
                return resp  # already a proper 429

            # stash for handler (optional)
            g.rate_limit = {"bucket": bucket, "remaining": rem, "reset": reset}

            rv = fn(*args, **kwargs)

            # always attach IP bucket headers to the outgoing response
            response = current_app.make_response(rv)
            try:
                response.headers.update(bucket.headers(rem, reset))
            except Exception:
                pass
            return response

        return _wrapped
    return _decorator


def perf_logged(*, warn_ms: Optional[int] = None, logger=None, include_query=False):
    """
    Log total handler time with endpoint + rule inferred from the request.

    Args:
      warn_ms: log at WARNING if elapsed >= warn_ms, else DEBUG.
      logger:  override logger; defaults to current_app.logger.
      include_query: include the query string in the logged path.

    Always logs, even on abort/exception. Never affects response flow.
    """
    def _decorator(fn):
        @functools.wraps(fn)
        def _wrap(*args, **kwargs):
            start = time.perf_counter()
            status = "-"
            try:
                rv = fn(*args, **kwargs)
                return rv
            finally:
                # Do NOT return from finally
                try:
                    enabled = bool(getattr(current_app, "config", {}).get("DEBUG_PERF", False))
                except Exception:
                    enabled = False

                if not enabled:
                    # Skip logging silently
                    pass
                else:
                    elapsed_ms = int((time.perf_counter() - start) * 1000)
                    try:
                        # Best-effort status extraction
                        if "rv" in locals():
                            try:
                                status = make_response(rv).status_code
                            except Exception:
                                pass

                        # Infer labels from the request
                        endpoint = request.endpoint or "-"          # e.g. "session.get_session"
                        rule     = getattr(request, "url_rule", None)
                        rule_s   = rule.rule if rule else request.path
                        path     = request.full_path if include_query else request.path

                        # Short function name (after blueprint) if helpful
                        # e.g., "session.get_session" -> "get_session"
                        short_fn = endpoint.split(".")[-1] if endpoint else "-"

                        # Compose message
                        msg = (
                            f"{request.method} {path} -> {status} "
                            f"[rule={rule_s} endpoint={endpoint} fn={short_fn}] "
                            f"took {elapsed_ms} ms"
                        )

                        log = logger or getattr(current_app, "logger", None)
                        if log:
                            if warn_ms is not None and elapsed_ms >= warn_ms:
                                log.warning(msg)
                            else:
                                log.debug(msg)
                    except Exception:
                        # Never let logging break the response
                        pass
        return _wrap
    return _decorator
