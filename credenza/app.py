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
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from werkzeug.utils import import_string
from werkzeug.exceptions import HTTPException
from .api.oidc_client import OIDCClientFactory
from .api.session.storage.session_store import SessionStore
from .api.session.storage.backends.base import create_storage_backend
from .api.util import AESGCMCodec
from .rest.session import session_blueprint
from .rest.login_flow import login_blueprint
from .rest.device_flow import device_blueprint
from .rest.discovery import discovery_blueprint
from .telemetry.audit.logger import init_audit_logger
from .telemetry.metrics.prometheus import metrics_blueprint
from .refresh.refresh_worker import run_refresh_worker

logger = logging.getLogger(__name__)


def configure_authn_env() -> None:
    """
    Load CREDENZA_* env vars from a .env file if present, otherwise
    fall back to sane defaults for any keys still unset.
    Hostname for URLs is taken from CONTAINER_HOSTNAME or system hostname.
    """
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
            load_dotenv(dotenv_path=fp, override=False)
            logger.info(f"Loaded dotenv configuration file from: {fp}")
            break

    # Determine base host (env override first)
    host = os.environ.get("CONTAINER_HOSTNAME", os.environ.get("HOSTNAME"))

    # Defaults for any missing CREDENZA_* vars
    defaults = {
        "CREDENZA_DEFAULT_REALM": "default",
        "CREDENZA_BASE_URL": f"https://{host}/authn",
        "CREDENZA_POST_LOGOUT_REDIRECT_URL": f"https://{host}/",
        "CREDENZA_ENABLE_PKCE": "true",
        "CREDENZA_ENABLE_LEGACY_API": "false",
        "CREDENZA_ENABLE_REFRESH_WORKER": "true",
        "CREDENZA_ENCRYPT_SESSION_DATA": "false",
        "CREDENZA_STORAGE_BACKEND": "memory",
        "CREDENZA_AUDIT_USE_SYSLOG": "false"
    }
    for key, fallback in defaults.items():
        os.environ.setdefault(key, fallback)


def load_config(app):
    configure_authn_env()
    app.config.from_prefixed_env(prefix="CREDENZA")

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

    # create session augmentation provider map
    provider_map = \
        {"default":
             import_string("credenza.api.session.augmentation.base_provider:DefaultSessionAugmentationProvider")()}
    for realm, prof in app.config["OIDC_IDP_PROFILES"].items():
        cls_path = prof.get("session_augmentation_provider")
        if cls_path:
            provider_map[realm] = import_string(cls_path)()
    app.config["SESSION_AUGMENTATION_PROVIDERS"] = provider_map


def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env(prefix="CREDENZA")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s", force=True)
    logging.getLogger("credenza").setLevel(
        logging.DEBUG if app.config.get("CREDENZA_DEBUG", app.config.get("DEBUG", False)) else logging.INFO)

    load_config(app)
    init_audit_logger(filename=app.config.get("AUDIT_LOGFILE_PATH", "credenza-audit.log"),
                      use_syslog=app.config.get("AUDIT_USE_SYSLOG", False))

    @app.errorhandler(HTTPException)
    def handle_http_exception(e):
        response = e.get_response()
        response.data = jsonify({
            "error": e.name.lower().replace(" ", "_"),
            "code": e.code,
            "message": e.description,
        }).data
        response.content_type = "application/json"
        return response

    @app.after_request
    def apply_secure_headers(response):
        if app.config["COOKIE_NAME"] in request.cookies:
            response.headers["Cache-Control"] = "private, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response

    app.config["OIDC_CLIENT_FACTORY"] = OIDCClientFactory(app.config["OIDC_IDP_PROFILES"])

    encrypt_session_data = app.config.get("ENCRYPT_SESSION_DATA", False)
    if app.config.get("ENCRYPTION_KEY"):
        app.config["CRYPTO_CODEC"] = AESGCMCodec(key=app.config["ENCRYPTION_KEY"])
    else:
        app.config["CRYPTO_CODEC"] = None
        if encrypt_session_data:
            encrypt_session_data = False
            logging.warning("Encryption of session data is disabled due to missing encryption key")

    storage_backend = create_storage_backend(app.config.get("STORAGE_BACKEND", "memory"),
                                             url=app.config.get("STORAGE_BACKEND_URL"))

    app.config["SESSION_STORE"] = SessionStore(
        storage_backend,
        ttl=app.config.get("SESSION_TTL", 2100),
        crypto_codec=app.config["CRYPTO_CODEC"] if encrypt_session_data == True else None
    )
    logger.debug(f"Encrypt session store data: {encrypt_session_data}")

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
    def worker():
        with app.app_context():
            logger.info("Starting background refresh worker")
            run_refresh_worker(app)

    # ensure we only start it once per process
    if app.config.get("ENABLE_REFRESH_WORKER", False) and not getattr(app, "_refresh_thread_started", False):
        Thread(target=worker, daemon=True).start()
        app._refresh_thread_started = True


if __name__ == "__main__":
    application = create_app()
    start_refresh_worker(application)
    port = application.config.get("SERVER_PORT", 8999)
    application.run(host="0.0.0.0", port=port)
