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
from flask import Blueprint, current_app, make_response, jsonify, abort

logger = logging.getLogger(__name__)

discovery_blueprint = Blueprint("discovery", __name__)

# This is a webauthn2 legacy compatibility endpoint
@discovery_blueprint.route("/discovery")
def discovery():
    if not current_app.config.get("ENABLE_LEGACY_API", False):
        abort(404)

    # validate oauth2 discovery scope, if specified
    discovery_info = {}
    profile = current_app.config["OIDC_IDP_PROFILES"].get(current_app.config["DEFAULT_REALM"])
    discovery_scopes = profile.get("discovery_scopes")
    if discovery_scopes is not None:
        accepted_scopes = accepted_scopes_to_set(profile)
        final_scopes = dict()
        for key in discovery_scopes.keys():
            if discovery_scopes[key] in accepted_scopes:
                final_scopes[key] = discovery_scopes[key]
            else:
                logger.debug(f"'{discovery_scopes[key]}' is configured as a discovery scope but not an accepted scope")
        discovery_info = {"oauth2_scopes" : final_scopes}

    return make_response(jsonify(discovery_info), 200)

def accepted_scopes_to_set(profile):
    scopes = set()
    acs = profile.get("accepted_scopes")
    if isinstance(acs, list):
        for s in acs:
            scope = s.get("scope")
            if scope is not None:
                scopes.add(scope)
    return scopes