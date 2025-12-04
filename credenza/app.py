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
from logging.handlers import SysLogHandler
from pathlib import Path
from threading import Thread
from dotenv import dotenv_values
from flask import Flask, jsonify, request
from requests import RequestException, ConnectionError, Timeout
from werkzeug.utils import import_string
from werkzeug.exceptions import HTTPException, BadGateway, ServiceUnavailable
from .api.oidc_client import OIDCClientFactory
from .api.session.storage.session_store import SessionStore
from .api.session.storage.backends.base import create_storage_backend
from .api.claim_mapper import build_realm_claim_maps
from .api.util import AESGCMCodec, is_browser_client
from .rest.session import session_blueprint
from .rest.login_flow import login_blueprint
from .rest.device_flow import device_blueprint
from .rest.discovery import discovery_blueprint
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
        try:
            return json.loads(v)
        except:
            return v
    app.config.update({
        # strip _ENV_PREFIX when copying
        (k[len(_ENV_PREFIX):], decode_json(v))
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

    # Optional trusted issuers
    trusted_path = app.config.get("TRUSTED_ISSUERS_FILE", "config/oidc_idp_trusted_issuers.json")
    if os.path.exists(trusted_path):
        with open(trusted_path) as f:
            app.config["TRUSTED_ISSUERS"] = json.load(f)
    else:
        app.config["TRUSTED_ISSUERS"] = []

    # Load the claim map
    app.config["IDP_CLAIM_MAPS"] = build_realm_claim_maps(app.config.get("OIDC_IDP_PROFILES"))

    # create session augmentation provider map
    provider_map = {}
    default_provider = "credenza.api.session.augmentation.base_provider:DefaultSessionAugmentationProvider"
    for realm, prof in app.config["OIDC_IDP_PROFILES"].items():
        cls_path = prof.get("session_augmentation_provider")
        if not cls_path:
            cls_path = default_provider
        provider_map[realm] = import_string(cls_path)()
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = provider_map

def init_logging(app):
    log_handler = logging.StreamHandler()
    log_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(process)d:%(threadName)s] [%(levelname)s] [%(name)s] - %(message)s"))

    syslog_socket = "/dev/log"
    if os.path.exists(syslog_socket) and os.access(syslog_socket, os.W_OK):
        try:
            log_handler = SysLogHandler(address=syslog_socket, facility=SysLogHandler.LOG_LOCAL1)
            log_handler.ident = "credenza: "
            log_handler.setFormatter(
                logging.Formatter("[%(process)d:%(threadName)s] [%(levelname)s] [%(name)s] - %(message)s"))
            logger.propagate = False
        except Exception as e:
            # fallback to preconfigured StreamHandler
            pass

    logger.addHandler(log_handler)
    logger.setLevel(logging.DEBUG if app.config.get("CREDENZA_DEBUG", app.config.get("DEBUG", False)) else logging.INFO)

def load_serialized_kwargs(raw_value) -> dict:
    """
    Safely parse a kwargs-like JSON string config to a dict.

    - None or empty/whitespace-only -> {}
    - Invalid JSON -> logs and returns {}
    - JSON that is not an object -> logs and returns {}
    """
    if raw_value is None:
        return {}

    if isinstance(raw_value, str):
        raw = raw_value.strip()
        if not raw:
            return {}
    else:
        # If someone has already put a dict here, just normalize.
        if isinstance(raw_value, dict):
            return raw_value
        raw = str(raw_value).strip()
        if not raw:
            return {}

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning(f"Invalid JSON in serialized kwargs={raw!r}; using empty dict: {e}")
        return {}

    if not isinstance(parsed, dict):
        logger.warning(f"Serialized kwargs should be a JSON object; got {type(parsed).__name__}; using empty dict")
        return {}

    return parsed

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

    # Bootstrap app
    app.config.from_prefixed_env(prefix="CREDENZA")
    init_logging(app)
    load_config(app)
    init_audit_logger(filename=app.config.get("AUDIT_LOGFILE_PATH", "credenza-audit.log"),
                      use_syslog=app.config.get("AUDIT_USE_SYSLOG", False))
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
                                             kwargs=load_serialized_kwargs(app.config.get("STORAGE_BACKEND_KWARGS")))

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
    app.register_blueprint(metrics_blueprint)
    if app.config.get("ENABLE_LEGACY_API", False):
        app.register_blueprint(discovery_blueprint)

    if app.config.get("ENABLE_HEALTH_CHECK", True):
        enable_healthcheck(app)

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
