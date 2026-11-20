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

    The entry whose id matches the block's authenticated_identity is marked
    with "authenticated": True. Only that identity was authenticated during
    this login; the others are linked accounts, bound to the user by a separate
    earlier linking ceremony and carrying their own (possibly lower) "ial".
    Consumers that make authorization decisions need to tell the two apart.

    default_identity is deliberately not surfaced. RAS documents it in two
    incompatible shapes -- a bare handle, and a pipe-delimited bracketed list
    ("<a@era.nih.gov>|<b@login.gov>") when several identities are linked -- and
    it carries no authorization meaning that "authenticated" plus the per-entry
    "ial" do not already express.

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
        by a federated_identities entry with the same id. The identity used to
        authenticate this session is marked with "authenticated": True.
        """
        by_id = {}

        for claim in self.FEDERATED_IDENTITY_CLAIMS:
            block = userinfo.get(claim)
            if not isinstance(block, dict):
                continue

            sources = block.get("sources") or {}
            identities = block.get("identities") or {}
            authenticated = self._handle(block.get("authenticated_identity"))
            matched_authenticated = False

            for source in set(sources) | set(identities):
                src_meta = sources.get(source) or {}
                detail = identities.get(source) or {}

                ident_id = self._handle(src_meta.get("identity_username"))
                if not ident_id:
                    # Without the identity_username we cannot form an id; skip.
                    logger.debug("RAS federated identity for source '%s' has no "
                                 "identity_username; skipping", source)
                    continue

                # Tracked before the dedup check below: an id already seen
                # under federated_identities_ial2 still accounts for this
                # block's authenticated_identity, and must not be reported as
                # unmatched.
                is_authenticated = bool(authenticated) and ident_id == authenticated
                if is_authenticated:
                    matched_authenticated = True

                if ident_id in by_id:
                    continue

                entry = {"iss": source, "provider": source}
                if is_authenticated:
                    entry["authenticated"] = True
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

            if authenticated and not matched_authenticated:
                logger.warning("RAS claim '%s' names authenticated_identity '%s' "
                               "with no matching source; no identity marked as "
                               "authenticated for this block", claim, authenticated)

        return by_id

    @staticmethod
    def _handle(value):
        """Return a RAS identity handle stripped of surrounding whitespace.

        RAS has been observed to emit identity handles with trailing whitespace
        (the partner developer guide's own samples show
        "samplename_pi@era.nih.gov "), which would otherwise defeat the
        comparison against authenticated_identity and produce identity ids that
        no ACL could match.
        """
        return value.strip() if isinstance(value, str) else None
