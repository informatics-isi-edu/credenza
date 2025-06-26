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
import time
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class SessionAugmentationProvider(ABC):
    """
    Extension points for sessions:
      • process_additional_tokens (some providers, e.g. Globus, may return additional dependent tokens in the token response)
      • fetch_dependent_tokens (some providers, e.g. Globus, allow clients to retrieve dependent tokens via token endpoints)
      • enrich_userinfo (add groups, roles, claims, etc. to userinfo from other sources)
      (additional as needed in future)
    """

    @abstractmethod
    def fetch_dependent_tokens(
        self,
        access_token: str,
        userinfo: dict,
        scopes: list[str] | None = None,
        access_type: str = "online"
    ) -> dict:
        """Fetch downstream or dependent tokens."""

    @abstractmethod
    def process_additional_tokens(self, tokens: dict, **kwargs) -> dict:
        """Post-process or filter additional or dependent tokens."""

    @abstractmethod
    def enrich_userinfo(self, userinfo: dict, additional_tokens: dict) -> None:
        """Augment userinfo with groups, roles, extra claims, etc."""


class DefaultSessionAugmentationProvider(SessionAugmentationProvider):
    def fetch_dependent_tokens(self, access_token, userinfo, scopes=None, access_type="online"):
        return {}

    def process_additional_tokens(self, tokens, cur_time=None):
        cur_time = cur_time or time.time()
        other_tokens = tokens.get("other_tokens", []) if isinstance(tokens, dict) else []
        dependent_tokens = tokens.get("dependent_tokens", []) if isinstance(tokens, dict) else []
        additional_tokens = {}

        def get_token_for_scopes(token):
            for s in token.get("scope", "").split():
                additional_tokens[s] = {
                    "access_token": t["access_token"],
                    "refresh_token": t.get("refresh_token"),
                    "expires_at": cur_time + t.get("expires_in", 0),
                    "resource_server": t.get("resource_server"),
                    "last_refresh_at": cur_time,
                    "refreshed_count": 0
                }

        if isinstance(tokens, list):
            for t in tokens:
                get_token_for_scopes(t)
        else:
            for t in other_tokens:
                get_token_for_scopes(t)
            for t in dependent_tokens:
                get_token_for_scopes(t)

        return additional_tokens

    def enrich_userinfo(self, userinfo, additional_tokens):
        return
