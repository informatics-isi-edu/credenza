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
import os
import json
import logging
from pathlib import Path
from threading import Thread
from dotenv import dotenv_values
from flask import Flask, jsonify, request, g
from requests import RequestException, ConnectionError, Timeout
from werkzeug.utils import import_string
from werkzeug.exceptions import HTTPException, BadGateway, ServiceUnavailable
from werkzeug.middleware.proxy_fix import ProxyFix
from .api.auth.client.adapters.adapter import list_adapters
from .api.auth.client.client_registry import load_client_registry
from .api.auth.oidc_client import OIDCClientFactory
from .api.session.storage.session_store import SessionStore
from .api.session.storage.backends.base import create_storage_backend
from .api.common.claim_mapper import build_realm_claim_maps
from .api.common.util import check_client_scope_coverage
from .api.common.rate_limit import FixedWindowJitterLimiter
from .api.common.crypto import AESGCMCodec
from .api.common.crypto import register_default_hashers
from .rest.helpers import is_browser_client, get_request_id
from .rest.session import session_blueprint
from .rest.login import login_blueprint
from .rest.device import device_blueprint
from .rest.discovery import discovery_blueprint
from .rest.token import token_blueprint
from .rest.introspect import introspect_blueprint
from .rest.metadata import metadata_blueprint
from .rest.authorize import authorize_blueprint
from .rest.consent import consent_blueprint
from .telemetry.audit.logger import init_audit_logger
from .telemetry.metrics.prometheus import metrics_blueprint
from .refresh.refresh_worker import run_refresh_worker

logger = logging.getLogger("credenza")


def load_config(app):
    """
    Load app.config with CREDENZA_* env vars from a .env file if present, os.environ, and
    fall back to sane defaults for any keys still unset.
    Hostname for URLs is taken from CONTAINER_HOSTNAME or system hostname.
    """
    # defaults for unconfigured variables
    env_config = {
        "CREDENZA_DEFAULT_REALM": "default",
        "CREDENZA_ENABLE_PKCE": "true",
        "CREDENZA_ENABLE_LEGACY_API": "false",
        "CREDENZA_ENABLE_REFRESH_WORKER": "true",
        "CREDENZA_ENCRYPT_SESSION_DATA": "false",
        "CREDENZA_STORAGE_BACKEND": "memory",
        "CREDENZA_AUDIT_USE_SYSLOG": "false",
        "CREDENZA_APP_USE_SYSLOG": "false",
        "CREDENZA_LEGACY_DEFAULT_RESOURCE": "urn:deriva:rest:service:all",
        "CREDENZA_DERIVED_SESSION_MAX_TTL": "1800",
    }

    # Load .env from one of these locations, if it exists
    dotenv_locations = [
        Path("/etc/credenza/credenza.env"),
        Path.home() / "credenza.env",
        Path("./config/credenza.env"),
        Path("./credenza.env")
    ]
    for fn in dotenv_locations:
        if fn.is_file():
            fp = str(fn)
            env_config.update(dotenv_values(dotenv_path=fp))
            logger.info(f"Loaded dotenv configuration file from: {fp}")
            break

    # os.environ overrides .env file
    env_config.update(os.environ.items())

    # Determine base host
    host = env_config.get("CONTAINER_HOSTNAME", env_config.get("HOSTNAME"))

    # deferred defaults that depend on configured host
    env_config.setdefault("CREDENZA_BASE_URL", f"https://{host}/authn")
    env_config.setdefault("CREDENZA_POST_LOGOUT_REDIRECT_URL", f"https://{host}/")

    _ENV_PREFIX = "CREDENZA_"
    def decode_json(v):
        if isinstance(v, str):
            try:
                return json.loads(v)
            except json.JSONDecodeError:
                return v
        return v
    app.config.update({
        # strip _ENV_PREFIX when copying
        k[len(_ENV_PREFIX):]: decode_json(v)
        for k, v in env_config.items()
        if k.startswith(_ENV_PREFIX)
    })

    legacy_mode = app.config.get("ENABLE_LEGACY_API", False)
    if not app.config.get("COOKIE_NAME"):
        app.config["COOKIE_NAME"] = "credenza" if not legacy_mode else "webauthn"

    # Load JSON realm config
    oidc_config_path = app.config.get("OIDC_IDP_PROFILES_FILE", "config/oidc_idp_profiles.json")
    if os.path.exists(oidc_config_path):
        with open(oidc_config_path) as f:
            app.config["OIDC_IDP_PROFILES"] = json.load(f)
    else:
        app.config["OIDC_IDP_PROFILES"] = {}

    # Optional service authentication (M2M) config
    service_auth_path = app.config.get("SERVICE_AUTH_FILE", "config/service_auth.json")
    if os.path.exists(service_auth_path):
        with open(service_auth_path) as f:
            app.config["SERVICE_AUTH"] = json.load(f)
    else:
        app.config["SERVICE_AUTH"] = {}

    # Optional client registry (OAuth2/RS/M2M) config
    logger.debug(f"Registered client authentication adapters: {set(list_adapters().keys())}")
    client_registry_path = app.config.get("CLIENT_REGISTRY_FILE", "config/client_registry.json")
    app.config["CLIENT_REGISTRY"] = load_client_registry(client_registry_path)

    _default_realm = app.config.get("DEFAULT_REALM")
    if _default_realm:
        _realm_profile = app.config["OIDC_IDP_PROFILES"].get(_default_realm, {})
        _issuable = _realm_profile.get("issuable_scopes")
        if _issuable is not None:
            check_client_scope_coverage(_issuable, app.config["CLIENT_REGISTRY"].clients)

    # Optional global consent labels (scope and resource URI display names for the consent page)
    consent_labels_path = app.config.get("CONSENT_LABELS_FILE", "config/consent_labels.json")
    if os.path.exists(consent_labels_path):
        with open(consent_labels_path) as f:
            app.config["CONSENT_LABELS"] = json.load(f)
    else:
        app.config["CONSENT_LABELS"] = {}

    # Optional trusted issuers
    trusted_path = app.config.get("TRUSTED_ISSUERS_FILE", "config/oidc_idp_trusted_issuers.json")
    if os.path.exists(trusted_path):
        with open(trusted_path) as f:
            app.config["TRUSTED_ISSUERS"] = json.load(f)
    else:
        app.config["TRUSTED_ISSUERS"] = []

    # Load the claim map
    app.config["IDP_CLAIM_MAPS"] = build_realm_claim_maps(app.config.get("OIDC_IDP_PROFILES"))

    # Create session augmentation provider map
    provider_map = {}
    default_provider = "credenza.api.session.augmentation.base_provider:DefaultSessionAugmentationProvider"
    for realm, prof in app.config["OIDC_IDP_PROFILES"].items():
        cls_path = prof.get("session_augmentation_provider")
        if not cls_path:
            cls_path = default_provider
        provider_map[realm] = import_string(cls_path)()
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = provider_map

    # Load secrets hashers
    register_default_hashers()

def init_logging(app):
    """Configure the credenza app logger.

    Always adds a stderr StreamHandler (for docker logs and local dev).
    Optionally adds a SysLogHandler on LOCAL1 when CREDENZA_APP_USE_SYSLOG
    is true, for non-Docker deployments where syslog is the only path to
    a centralized collector.  In Docker, driver: syslog in compose already
    forwards stderr, so enabling this would duplicate every app log line.
    """
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(process)d:%(threadName)s] [%(levelname)s] [%(name)s] - %(message)s"))
    logger.addHandler(stream_handler)
    logger.propagate = False

    if app.config.get("APP_USE_SYSLOG", False):
        syslog_socket = "/dev/log"
        if os.path.exists(syslog_socket) and os.access(syslog_socket, os.W_OK):
            from logging.handlers import SysLogHandler

            try:
                sh = SysLogHandler(address=syslog_socket, facility=SysLogHandler.LOG_LOCAL1)
                sh.ident = "credenza: "
                sh.setFormatter(
                    logging.Formatter("[%(process)d:%(threadName)s] [%(levelname)s] [%(name)s] - %(message)s"))
                logger.addHandler(sh)
            except Exception:
                pass

    logger.setLevel(logging.DEBUG if app.config.get("CREDENZA_DEBUG", app.config.get("DEBUG", False)) else logging.INFO)

def load_serialized_kwargs(input_kwargs):
   if not input_kwargs:
      return {}

   if isinstance(input_kwargs, dict):
       return input_kwargs

   try:
      parsed = json.loads(input_kwargs)
      if not isinstance(parsed, dict):
         logger.warning(f"Serialized kwargs should be a JSON object; got {type(parsed).__name__}; using empty dict")
         return {}
      return parsed
   except Exception as e:
      logger.warning(f"Invalid JSON in serialized kwargs={input_kwargs!r}; using empty dict: {e}")
      return {}

def create_app():
    app = Flask(__name__)

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        response = e.get_response()
        if is_browser_client(request):
            return response
        response.data = jsonify({
            "error": e.name.lower().replace(" ", "_"),
            "code": e.code,
            "message": e.description,
        }).data
        response.content_type = "application/json"
        return response

    @app.errorhandler(RequestException)
    def handle_requests_exc(e):
        try:
            logger.error(f"Unhandled exception during external HTTP request: {e}")
            msg = "Upstream request %s. Check service log for additional details."
            if isinstance(e, (Timeout, ConnectionError)):
                raise ServiceUnavailable(description=msg % "incomplete") from e
            raise BadGateway(description=msg % "failed") from e
        except HTTPException as he:
            return handle_http_exception(he)

    @app.after_request
    def apply_secure_headers(response):
        if app.config["COOKIE_NAME"] in request.cookies:
            response.headers["Cache-Control"] = "private, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response

    @app.after_request
    def add_rid(resp):
        rid = getattr(g, "rid", None) or get_request_id(request.headers)
        resp.headers.setdefault("X-Request-Id", rid)
        return resp

    # Bootstrap app
    app.config.from_prefixed_env(prefix="CREDENZA")
    init_logging(app)
    load_config(app)
    # if logger.isEnabledFor(logging.DEBUG):
    #     logger.debug(f"Config loaded: {app.config}")

    if app.config.get("ENABLE_PROXYFIX", False):
        # Default: one proxy hop (Reverse Proxy -> Credenza)
        proxy_depth = app.config.get("PROXYFIX_DEPTH", 1)
        logger.info(f"Enabling ProxyFix with depth {proxy_depth}")
        app.wsgi_app = ProxyFix(app.wsgi_app,
                                x_for=proxy_depth,
                                x_proto=proxy_depth,
                                x_host=proxy_depth,
                                x_port=proxy_depth)

    init_audit_logger(use_syslog=app.config.get("AUDIT_USE_SYSLOG", False))
    app.config["OIDC_CLIENT_FACTORY"] = OIDCClientFactory(app.config["OIDC_IDP_PROFILES"])

    # To encrypt or not to encrypt (session data)
    encrypt_session_data = app.config.get("ENCRYPT_SESSION_DATA", False)
    if encrypt_session_data and app.config.get("ENCRYPTION_KEY"):
        app.config["CRYPTO_CODEC"] = AESGCMCodec(key=app.config["ENCRYPTION_KEY"])
    else:
        app.config["CRYPTO_CODEC"] = None
        if encrypt_session_data:
            encrypt_session_data = False
            logging.warning("Encryption of session data is disabled due to missing encryption key")

    # Create the storage backend and instantiate the session store
    storage_backend = create_storage_backend(app.config.get("STORAGE_BACKEND", "memory"),
                                             url=app.config.get("STORAGE_BACKEND_URL"),
                                             **load_serialized_kwargs(app.config.get("STORAGE_BACKEND_KWARGS")))

    app.config["SESSION_STORE"] = SessionStore(
        storage_backend,
        ttl=app.config.get("SESSION_TTL", 2100),
        crypto_codec=app.config["CRYPTO_CODEC"] if encrypt_session_data == True else None
    )
    logger.debug(f"Encrypt session store data: {encrypt_session_data}")

    # Register REST API blueprints
    app.register_blueprint(session_blueprint)
    app.register_blueprint(login_blueprint)
    app.register_blueprint(device_blueprint)
    app.register_blueprint(token_blueprint)
    app.register_blueprint(introspect_blueprint)
    app.register_blueprint(metadata_blueprint)
    app.register_blueprint(authorize_blueprint)
    app.register_blueprint(consent_blueprint)
    app.register_blueprint(metrics_blueprint)
    if app.config.get("ENABLE_LEGACY_API", False):
        app.register_blueprint(discovery_blueprint)

    if app.config.get("ENABLE_HEALTH_CHECK", True):
        enable_healthcheck(app)

    app.extensions["rate_limits"] = {
        "10_per_min": FixedWindowJitterLimiter(limit=10, window_sec=60),
        "30_per_min": FixedWindowJitterLimiter(limit=30, window_sec=60),
        "60_per_min": FixedWindowJitterLimiter(limit=60, window_sec=60),
    }

    return app

def enable_healthcheck(app):
    """Health check endpoint for load balancers or other orchestration"""
    @app.route('/health')
    def health_check():
        return jsonify({"status": "healthy", "service": "credenza"}), 200

def start_refresh_worker(app):
    def refresh_worker():
        with app.app_context():
            logger.info("Starting background refresh worker")
            run_refresh_worker(app)

    # ensure we only start it once per process
    if app.config.get("ENABLE_REFRESH_WORKER", False) and not getattr(app, "_refresh_thread_started", False):
        Thread(target=refresh_worker, daemon=True).start()
        app._refresh_thread_started = True


if __name__ == "__main__":
    application = create_app()
    start_refresh_worker(application)
    port = application.config.get("SERVER_PORT", 8999)
    application.run(host="0.0.0.0", port=port)
