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
from .base_provider import DefaultSessionAugmentationProvider

logger = logging.getLogger(__name__)


class RasSessionAugmentationProvider(DefaultSessionAugmentationProvider):
    """Session augmentation provider for NIH Research Authorization Service (RAS).

    This provider canonicalizes the federated identities that RAS returns for an
    authenticated user into the shared "identities" claim that resource servers
    consume. RAS reports federated identities under federated_identities_ial2
    (IAL2-verified) and/or federated_identities. Each block is keyed by source
    provider (e.g. login.gov) and is split across two parallel sub-blocks:

      "sources": {
        "login.gov": {"identity_username": "...", "ial": 2, "identity_sub": "..."}
      },
      "identities": {
        "login.gov": {"mail": "...", "userid": "...", "firstname": "...", "lastname": "..."}
      }

    The identity id is sources[src].identity_username (e.g.
    "<userid>@login.gov", which matches RAS's own default_identity /
    authenticated_identity handle); the upstream OIDC subject
    (sources[src].identity_sub) and the profile detail (identities[src]) are
    carried as detail. They are paired by source key and canonicalized into a
    dict keyed by identity_username whose value is the per-identity detail.

    NOTE: Full GA4GH Passport / Visa parsing (ADR-0005) is not implemented here
    yet. This provider currently covers only the federated identity mapping.
    """

    FEDERATED_IDENTITY_CLAIMS = ("federated_identities_ial2", "federated_identities")

    def build_identities(self, userinfo):
        """Return a canonical identities map from the RAS federated identity claims.

        The result is a dict keyed by the identity id (sources[src].
        identity_username), whose values hold the per-identity detail. Keying by
        id lets legacy consumers read the id strings (the keys) without
        descending into the detail. IAL2-verified identities take precedence; an
        identity already seen under federated_identities_ial2 is not overwritten
        by a federated_identities entry with the same id.
        """
        by_id = {}

        for claim in self.FEDERATED_IDENTITY_CLAIMS:
            block = userinfo.get(claim)
            if not isinstance(block, dict):
                continue

            sources = block.get("sources") or {}
            identities = block.get("identities") or {}

            for source in set(sources) | set(identities):
                src_meta = sources.get(source) or {}
                detail = identities.get(source) or {}

                ident_id = src_meta.get("identity_username")
                if not ident_id:
                    # Without the identity_username we cannot form an id; skip.
                    logger.debug("RAS federated identity for source '%s' has no "
                                 "identity_username; skipping", source)
                    continue

                if ident_id in by_id:
                    continue

                entry = {"iss": source, "provider": source}
                if src_meta.get("identity_sub"):
                    entry["sub"] = src_meta["identity_sub"]
                if src_meta.get("ial") is not None:
                    entry["ial"] = src_meta["ial"]
                if detail.get("mail"):
                    entry["email"] = detail["mail"]
                if detail.get("userid"):
                    entry["userid"] = detail["userid"]
                name = " ".join(
                    p for p in (detail.get("firstname"), detail.get("lastname")) if p
                ).strip()
                if name:
                    entry["name"] = name

                by_id[ident_id] = entry

        return by_id
