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
from http.client import HTTPException

import requests
import logging
from flask import current_app, abort
from .base_provider import DefaultSessionAugmentationProvider
from ...util import get_effective_scopes
from ...session.storage.session_store import SessionData
from ....telemetry import audit_event

logger = logging.getLogger(__name__)


class GlobusSessionAugmentationProvider(DefaultSessionAugmentationProvider):

    GLOBUS_ISSUER = "https://auth.globus.org"
    GLOBUS_GROUPS_URL = "https://groups.api.globus.org/v2/groups/my_groups"
    GLOBUS_GROUPS_SCOPE = 'urn:globus:auth:scope:groups.api.globus.org:view_my_groups_and_memberships'
    GLOBUS_DEPENDENT_TOKEN_GRANT_TYPE = "urn:globus:auth:grant_type:dependent_token"

    def fetch_dependent_tokens(self, access_token, userinfo, scopes=None, access_type="offline"):
        user = userinfo.get("email")
        iss = userinfo.get("iss")

        if iss == self.GLOBUS_ISSUER:
            logger.debug(f"Getting additional Globus dependent tokens for {user}")

            realm = current_app.config["DEFAULT_REALM"]
            factory = current_app.config["OIDC_CLIENT_FACTORY"]
            client = factory.get_client(realm)
            try:
                # attempt to get dependent tokens
                tokens = client.fetch_dependent_tokens(access_token=access_token,
                                                       grant_type=self.GLOBUS_DEPENDENT_TOKEN_GRANT_TYPE,
                                                       scope=scopes,
                                                       access_type=access_type)
                logger.debug(f"Dependent tokens fetched successfully")
                return self.process_additional_tokens(tokens)
            except Exception as e:
                logger.warning(
                    f"Failed to fetch dependent tokens, Globus groups and any other dependent tokens will not "
                    f"be available : {e}")
        else:
            logger.warning(f"Globus dependent token fetch not possible for {iss}")

        return {}

    def enrich_userinfo(self, userinfo, additional_tokens):
        user = userinfo.get("email")
        iss = userinfo.get("iss")

        if self.GLOBUS_ISSUER == iss:
            logger.debug(f"Getting additional Globus groups for {user}")
            tokens = additional_tokens.get(self.GLOBUS_GROUPS_SCOPE)
            if tokens:
                access_token = tokens.get("access_token")
            else:
                logger.debug(f"Tokens for {self.GLOBUS_GROUPS_SCOPE} not found")
                return

            try:
                headers = {"Authorization": f"Bearer {access_token}"}
                resp = requests.get(self.GLOBUS_GROUPS_URL, headers=headers, timeout=5)
                resp.raise_for_status()
                # logger.debug(f"Globus groups response: %s" % resp.json())
                groups = [
                    {"id": iss + "/" + g["id"], "display_name": g["name"]} for g in resp.json()
                ]
                existing_groups = userinfo.get("groups", [])
                if existing_groups:
                    existing_groups.extend(groups)
                else:
                    userinfo["groups"] = groups
                logger.debug(f"Augmented userinfo with {len(groups)} Globus groups.")
            except Exception as e:
                logger.warning(f"Failed to fetch Globus groups: {e}")

    def session_from_bearer_token(self, bearer_token) -> (str, SessionData):
        realm = current_app.config["DEFAULT_REALM"]
        factory = current_app.config["OIDC_CLIENT_FACTORY"]
        store = current_app.config["SESSION_STORE"]
        client = factory.get_client(realm)

        # Check if we already have a session created by this token. In this case the passed-in token is a Globus bearer
        # token, since we return it as the session key upon success
        sid, session = store.get_session_by_session_key(bearer_token)
        if sid and session:
            return sid, session

        logger.debug(f"Attempting to create session from bearer token")
        try:
            # first, we need to introspect the access token
            params = {
                "include": "identity_set_detail"} if client.issuer == self.GLOBUS_ISSUER else {}
            userinfo = client.validate_access_token(bearer_token, required_audience=client.client_id, **params)
        except Exception as e:
            logger.warning(f"Could not create session from bearer token. Token introspection and validation failed: {e}")
            abort(404)

        # now verify that the scopes found in the token match our whitelisted set of accepted scopes
        scopes = userinfo.get("scope", "")
        accepted_scopes = client.profile.get('accepted_scopes', [])
        matched_scope = False
        for a in accepted_scopes:
            if a.get('scope') in scopes:
                if a.get("issuer") == userinfo.get('iss'):
                    matched_scope = True
                    break
        if not matched_scope:
            logger.debug("Bad scope or issuer for bearer token")
            abort(404)

        # Augment the session, if applicable
        # attempt to get any dependent tokens
        additional_tokens = self.fetch_dependent_tokens(bearer_token, userinfo)
        # possibly get additional groups using external tokens or other means (e.g. Globus)
        self.enrich_userinfo(userinfo, additional_tokens)

        store = current_app.config["SESSION_STORE"]
        session_id = store.generate_session_id()
        session_key, session_data = store.create_session(
            session_id=session_id,
            access_token=bearer_token,
            scopes=scopes,
            userinfo=userinfo,
            realm=realm,
            metadata={},
            additional_tokens=additional_tokens,
            use_access_token_as_session_key=True
        )

        sub = userinfo.get("sub")
        user = userinfo.get("email")
        audit_event("session_from_bearer_token",
                    session_id=session_id,
                    user=user,
                    sub=sub,
                    scopes=get_effective_scopes(session_data),
                    realm=realm)
        logger.info(
            f"Session creation from bearer token successful for user {user} ({sub}) with session id {session_id} "
            f"on realm {realm}.")

        return session_key, session_data