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
import logging
from urllib.parse import urlparse
from flask import Blueprint, current_app, Response
import json

logger = logging.getLogger(__name__)

metadata_blueprint = Blueprint("metadata", __name__)


def rfc8414_discovery_url(base_url: str) -> str:
    """
    Compute the RFC 8414 Section 2 discovery URL for a given issuer URL.

    For an issuer with no path (https://host), the URL is:
        https://host/.well-known/oauth-authorization-server
    For an issuer with a path prefix (https://host/authn), the URL is:
        https://host/.well-known/oauth-authorization-server/authn

    In path-prefix deployments (WSGIScriptAlias /authn), a reverse-proxy
    rewrite rule must expose this URL since Flask cannot serve paths outside
    its own SCRIPT_NAME boundary.
    """
    parsed = urlparse(base_url.rstrip("/"))
    path = parsed.path.rstrip("/")
    well_known = f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-authorization-server"
    return f"{well_known}{path}" if path else well_known


@metadata_blueprint.route("/.well-known/oauth-authorization-server", methods=["GET"])
def oauth_authorization_server_metadata():
    """
    RFC 8414 OAuth 2.0 Authorization Server Metadata.

    Returns a static discovery document advertising Credenza's OAuth endpoints.
    Required by clients to discover the authorization and token endpoints.
    No authentication required on this endpoint.
    """
    base = current_app.config["BASE_URL"].rstrip("/")

    default_realm = current_app.config.get("DEFAULT_REALM")
    idp_profiles = current_app.config.get("OIDC_IDP_PROFILES") or {}
    realm_profile = idp_profiles.get(default_realm) or {} if default_realm else {}
    if "issuable_scopes" in realm_profile:
        scopes_supported = sorted(set(realm_profile["issuable_scopes"]))
    else:
        scopes_str = realm_profile.get("scopes", "")
        scopes_supported = sorted({s for s in scopes_str.split() if s})

    metadata = {
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "device_authorization_endpoint": f"{base}/device_authorization",
        "introspection_endpoint": f"{base}/introspect",
        "revocation_endpoint": f"{base}/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": [
            "authorization_code",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
            "urn:ietf:params:oauth:grant-type:token-exchange",
        ],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
        ],
        "revocation_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "resource_indicators_supported": True,
    }

    if scopes_supported:
        metadata["scopes_supported"] = scopes_supported

    return Response(
        json.dumps(metadata, indent=2),
        status=200,
        mimetype="application/json",
        headers={"Cache-Control": "public, max-age=3600"},
    )