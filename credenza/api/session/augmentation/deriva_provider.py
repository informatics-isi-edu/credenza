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
import requests
import logging
from requests import HTTPError
from flask import current_app, g
from .base_provider import DefaultSessionAugmentationProvider
from ...util import get_realm

logger = logging.getLogger(__name__)


class DerivaSessionAugmentationProvider(DefaultSessionAugmentationProvider):

    def enrich_userinfo(self, userinfo, additional_tokens):
        user = userinfo.get("email")
        profile = current_app.config["OIDC_IDP_PROFILES"].get(get_realm(), {})
        params = profile.get("session_augmentation_params", {})
        groups_api_url = params.get("groups_api_url")
        if not groups_api_url:
            logger.warning(f"Parameter 'groups_api_url' was not found in 'session_augmentation_params' configuration block of profile.")
            return False
        else:
            groups_api_url = groups_api_url.rstrip("/")

        try:
            headers = {'Authorization': f'Bearer {g.session_key}'}
            resp = requests.get(groups_api_url + "/my",
                                headers=headers,
                                timeout=5,
                                verify=not params.get("groups_api_bypass_cert_verify", False))
            resp.raise_for_status()
            #logger.debug(f"DERIVA groups response: %s" % resp.json())
            groups = resp.json().get("groups", {})
            groups = [
                {"id": groups_api_url + "/" + g["id"], "display_name": g["name"]} for g in groups
            ]
            existing_groups = userinfo.get("groups", [])
            if existing_groups:
                existing_groups.extend(groups)
            else:
                userinfo["groups"] = groups
            logger.debug(f"Augmented userinfo for {user} with {len(groups)} DERIVA groups.")
            return True
        except HTTPError as e:
            if e.response.status_code == 401:
                logger.debug("Authentication failed when trying to retrieve DERIVA groups.")
        except Exception as e:
            logger.warning(f"Failed to fetch DERIVA groups: {e}")

        return False