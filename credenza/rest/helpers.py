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
import re
import json
import time
import uuid
import hashlib
import ipaddress
import functools
import logging
from typing import Optional, Mapping
from flask import Response, request, jsonify, abort, current_app, make_response, g
from publicsuffix2 import get_sld
from ..telemetry import audit_event
from ..api.auth.client.client_registry import ClientRegistry, ClientRecord, DEFAULT_CLIENT_AUTH_MAX_SESSION_TTL
from ..api.auth.client.adapters.adapter import ProofContext, AdapterResult, AdapterAuthError, AdapterError
from ..api.common import client_ip
from ..api.common.errors import OAuthError
from ..api.common.util import parse_basic_auth, normalize_str_list
from ..api.common.grant_type import GrantType, map_grant_type_to_session_type  # noqa: F401

logger = logging.getLogger(__name__)

def make_json_response(data):
    return Response(
        json.dumps(data, sort_keys=False),  # Preserve key order
        mimetype="application/json"
    )


def route_label(req):
    # Prefer the matched rule (shows which alias hit), else fallback to request path
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


def validate_client(client_registry:ClientRegistry, proof_context:ProofContext):
    # Extract client_id: prefer Authorization Basic, else form client_id
    parsed = parse_basic_auth(request.headers.get("authorization"))
    client_id = (parsed["client_id"] if parsed else None) or proof_context.get("client_id")

    # require client_id per policy
    if not client_id:
        audit_event("request_missing_client_id", request_id=get_request_id())
        abort(400, description=OAuthError.INVALID_REQUEST)

    # resolve client from registry
    client_rec = client_registry.get(client_id)
    if client_rec is None:
        if current_app.config.get("ALLOW_UNREGISTERED_CLIENTS", False):
            return None
        audit_event("request_unknown_client", client_id=client_id)
        abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

    # ensure client is enabled (disabled clients are always rejected)
    if not client_rec.enabled:
        audit_event("request_disabled_client", client_id=client_id)
        abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

    return client_rec


def validate_grant_type(proof_context: ProofContext, client_rec: Optional[ClientRecord]) -> GrantType:
    # Extract grant_type
    grant_type_input = proof_context.get("grant_type") or ""
    grant_type_input = grant_type_input.strip()
    if not grant_type_input:
        audit_event(
            "token_request_missing_grant_type", request_id=get_request_id())
        abort(400, description=OAuthError.INVALID_REQUEST)

    # First, ensure it's a syntactically/semantically known grant type
    try:
        grant_type = GrantType(grant_type_input)
    except ValueError:
        logger.error(f"Unsupported grant type in request: {grant_type_input}")
        audit_event(
            "token_request_unsupported_grant_type",
            request_id=get_request_id(),
            grant_type=grant_type_input,
            client_id=client_rec.client_id if client_rec is not None else None,
            allowed_grants=client_rec.allowed_grant_types if client_rec is not None else None,
        )
        abort(400, description=OAuthError.INVALID_REQUEST)

    # Then ensure the parsed grant type is allowed for this client - if provided
    if client_rec is not None:
        allowed_grants = client_rec.allowed_grant_types or []
        if grant_type not in allowed_grants and grant_type_input not in allowed_grants:
            audit_event(
                "token_request_invalid_grant_type_for_client",
                request_id=get_request_id(),
                grant_type=grant_type,
                client_id=client_rec.client_id,
                allowed_grants=allowed_grants,
            )
            abort(401, description=OAuthError.UNAUTHORIZED_CLIENT)

    return grant_type


def adapter_authenticate(proof_context:ProofContext, client_rec: ClientRecord):
    # Get adapter instance from client record (already constructed by registry)
    client_id = client_rec.client_id
    adapter = client_rec.adapter_instance
    if adapter is None:
        logger.error(f"confidential client {client_id} has no valid authentication adapter_instance configured")
        audit_event("token_request_misconfigured_client_adapter", client_id=client_id)
        abort(500, description=OAuthError.SERVER_ERROR)

    # Authenticate via adapter.authenticate (returns an AdapterResult or raises AdapterAuthError/AdapterError)
    try:
        ar: AdapterResult = adapter.authenticate(
            proof_context=proof_context, allowed_methods=client_rec.allowed_auth_methods)
    except AdapterAuthError as e:
        audit_event("token_request_adapter_auth_error",
                    request_id=get_request_id(),
                    client_id=client_id,
                    error_code=e.error_code,
                    error=str(e))
        abort(e.status, description=OAuthError.get(e.error_code))
    except AdapterError as e:
        logger.error(f"adapter error while authenticating client={client_id}: {str(e)}")
        audit_event("token_request_adapter_failure", client_id=client_id, error=str(e))
        abort(500, description=OAuthError.SERVER_ERROR)

    return ar


_TRACEPARENT_RE = re.compile(r"^[0-9a-f]{2}-([0-9a-f]{32})-[0-9a-f]{16}-[0-9a-f]{2}$", re.IGNORECASE)

def get_request_id(headers: Optional[Mapping[str, str]] = None) -> str:
    """
    Return a stable request id for the current Flask request.

    - Reuses a cached id stored on flask.g if present.
    - Prefer W3C `traceparent` (extracts the trace-id portion).
    - Fall back to common correlation headers.
    - Last-resort: generate a UUID once and cache it on g.
    """
    # use provided headers (test-friendly) or the current request headers
    if headers is None:
        headers = request.headers

    # return cached id if already computed for this request
    cid = getattr(g, "request_id", None)
    if cid:
        return cid

    # 1) W3C Trace Context: try to extract the trace-id (more compact & stable)
    tp = headers.get("traceparent")
    if tp:
        tp = tp.strip()
        m = _TRACEPARENT_RE.match(tp)
        if m:
            cid = m.group(1)
        else:
            # fallback to returning the whole header if it doesn't match expected pattern
            cid = tp
        g.request_id = cid
        return cid

    # 2) common correlation/request id headers (case-insensitive via headers.get)
    for h in (
        "X-Request-Id",
        "X-Request-ID",
        "x-request-id",
        "X-Correlation-Id",
        "X-Correlation-ID",
        "x-correlation-id",
        "X-Amzn-Trace-Id",
        "x-amzn-trace-id",
    ):
        v = headers.get(h)
        if v:
            cid = v.strip()
            g.request_id = cid
            return cid

    # 3) Last resort: create one, store it and return
    cid = str(uuid.uuid4())
    g.request_id = cid
    return cid


def get_cookie_domain() -> Optional[str]:
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


def is_browser_client(req):  # pragma: no cover
    accept = (req.headers.get("Accept") or "").lower()
    content_type = (req.headers.get("Content-Type") or "").lower()

    # If the client is clearly asking for JSON, treat as API
    if "application/json" in accept or content_type.startswith("application/json"):
        return False

    # Classic XHR signal (some libs still set this)
    if (req.headers.get("X-Requested-With") or "").lower() == "xmlhttprequest":
        return False

    # Modern browser fetch/navigation signals:
    # - navigate/document => likely real browser page load
    # - cors/no-cors/same-origin + not document => likely fetch/xhr
    sfm = (req.headers.get("Sec-Fetch-Mode") or "").lower()
    sfd = (req.headers.get("Sec-Fetch-Dest") or "").lower()

    if sfm:
        if sfm == "navigate" and (sfd == "document" or not sfd):
            return True
        # Anything else is usually fetch/xhr/subresource
        return False

    # Fallback when Sec-Fetch-* is absent:
    # Only treat as browser when HTML is *specifically* acceptable.
    # (Still keep JSON as the safer default.)
    if "text/html" in accept or "application/xhtml+xml" in accept:
        return True

    return False


def ip_rate_limited(unknown_bucket="10_per_min", normal_bucket="30_per_min"):
    """
    Decorator that enforces an IP-based rate limit and adds its headers
    to the final response. Stashes details in g.rate_limit for handlers.

    Set app.config["ENABLE_RATE_LIMITING"] = False to bypass entirely.

    Usage:
      @service_blueprint.route("/token", methods=["POST"])
      @ip_rate_limited()
      def issue_token(): ...
    """
    def _decorator(fn):
        @functools.wraps(fn)
        def _wrapped(*args, **kwargs):
            # Bypass completely if disabled (default: enabled)
            enabled = current_app.config.get("ENABLE_RATE_LIMITING", True)
            if not enabled:
                return fn(*args, **kwargs)

            limits = current_app.extensions["rate_limits"]
            ip = client_ip(request)
            ip_key = f"ip:{ip}"
            detail = f"Too many requests: {route_label(request)} from: {ip_key}"
            bucket = limits[unknown_bucket] if ip == "unknown" else limits[normal_bucket]

            resp, rem, reset = limit_or_429(bucket, ip_key, detail)
            if resp is not None:
                logger.debug(detail)
                return resp  # already a proper 429

            # stash for handler (optional)
            g.rate_limit = {"bucket": bucket, "remaining": rem, "reset": reset}

            rv = fn(*args, **kwargs)

            # always attach IP bucket headers to the outgoing response
            response = current_app.make_response(rv)
            try:
                response.headers.update(bucket.headers(rem, reset))
            except Exception: # pragma: no cover
                pass
            return response

        return _wrapped
    return _decorator


def rate_limit_principal_key(principal: str, *, realm: str = "", adapter: str = "") -> str:
    # Normalize for stability
    p = (principal or "").strip()
    material = "\n".join([realm or "", adapter or "", p]).encode("utf-8", errors="surrogatepass")
    digest = hashlib.sha256(material).hexdigest()[:24]  # short, bounded
    return f"principal:{digest}"


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
                except Exception: # pragma: no cover
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
                            except Exception: # pragma: no cover
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
