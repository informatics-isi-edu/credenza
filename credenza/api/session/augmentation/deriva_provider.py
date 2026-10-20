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
import re
import requests
import logging
from urllib.parse import quote
from requests import HTTPError
from flask import current_app, g
from .base_provider import DefaultSessionAugmentationProvider
from .ras_provider import RasSessionAugmentationProvider
from ....api.common.util import extract_session_key
from ....api.common.claim_mapper import get_claim_map_for_realm, resolve_claim

logger = logging.getLogger(__name__)


class DerivaGroupsSessionAugmentationProvider(DefaultSessionAugmentationProvider):

    def enrich_userinfo(self, userinfo, additional_tokens):
        user = userinfo.get("email")
        params = self.params
        groups_api_url = params.get("groups_api_url")
        if not groups_api_url:
            logger.warning(f"Parameter 'groups_api_url' was not found in 'session_augmentation_params' configuration block of profile.")
            return False
        else:
            groups_api_url = groups_api_url.rstrip("/")

        try:
            # Determine current auth method
            if hasattr(g, "session_key"):
                auth = g.session_key
            else:
                auth,_ = extract_session_key()

            headers = {'Authorization': f'Bearer {auth}'}
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


class DerivaErmrestSessionAugmentationProvider(DefaultSessionAugmentationProvider):
    """Session augmentation provider that maps a user to roles/groups via ERMrest.

    The realm profile's session_augmentation_params carries a list of templated
    ERMrest queries under "ermrest_role_queries". Each query is run with the
    user's own session key as its bearer credential, so ERMrest ACLs bound what
    the query can see in addition to the identity filter in the URL. Each result
    row is rendered into a {"id", "display_name"} entry and added to the
    configured userinfo claim ("roles" by default, or "groups"), which credenza
    then presents as ACL attributes.

      "session_augmentation_params": {
        "defer_augmentation": true,
        "ermrest_role_queries": [
          {
            "name": "assigned_roles",
            "url": "https://host/ermrest/catalog/1/attribute/s:user_role/user={client_id}/s:role/name,description",
            "claim": "roles",
            "id": "tag:example.org,2026:role/{name}",
            "display_name": "{description}"
          }
        ]
      }

    URL templates may only reference the identity of the authenticated subject:
    {client_id} (the "<iss>/<sub>" id that ERMrest sees as the client and records
    in ERMrest_client.ID and RCB/RMB), {iss} and {sub}. Values are percent-encoded
    before substitution. Linked identities are never offered: they are not ACL
    principals, so they must not be a route to acquiring roles either. The id and
    display_name templates reference columns of the result row, unencoded.

    defer_augmentation is required. The non-deferred augmentation pass runs
    before the session exists, so there is no session key to present to ERMrest.

    Each run replaces the entries this provider added on the previous run rather
    than appending to them. Those ids are recorded under AUGMENTED_KEY so they can
    be removed without disturbing groups or roles that came from the IdP. Failure
    is closed: a query that fails contributes nothing, so its earlier entries are
    dropped rather than kept stale.
    """

    AUGMENTED_KEY = "deriva_ermrest_augmented"
    ALLOWED_CLAIMS = ("roles", "groups")
    PLACEHOLDER = re.compile(r"\{(\w+)\}")

    def enrich_userinfo(self, userinfo, additional_tokens):
        enriched = super().enrich_userinfo(userinfo, additional_tokens)
        self._remove_previous_entries(userinfo)

        realm = self.realm
        params = self.params
        queries = params.get("ermrest_role_queries")
        if not queries:
            logger.warning("Parameter 'ermrest_role_queries' was not found in "
                           "'session_augmentation_params' of profile '%s'.", realm)
            return enriched

        if hasattr(g, "session_key"):
            auth = g.session_key
        else:
            auth, _ = extract_session_key()
        if not auth:
            logger.warning("No session key available for ERMrest role mapping on realm '%s'; "
                           "this provider requires 'defer_augmentation': true.", realm)
            return enriched

        identity = self._identity_values(userinfo, realm)
        if not identity.get("client_id"):
            logger.warning("Cannot determine client id for ERMrest role mapping on realm '%s'.", realm)
            return enriched

        added = {}
        for query in queries:
            entries = self._run_query(query, identity, auth, params)
            if entries is None:
                continue
            enriched = True
            claim = query.get("claim", "roles")
            existing = userinfo.get(claim)
            if not isinstance(existing, list):
                existing = [existing] if existing else []
            seen = {e["id"] if isinstance(e, dict) else e for e in existing}
            for entry in entries:
                if entry["id"] in seen:
                    continue
                seen.add(entry["id"])
                existing.append(entry)
                added.setdefault(claim, []).append(entry["id"])
            userinfo[claim] = existing

        if added:
            userinfo[self.AUGMENTED_KEY] = added
        logger.debug("Augmented userinfo for %s with %d ERMrest role entries.",
                     identity["client_id"], sum(len(v) for v in added.values()))
        return enriched

    @staticmethod
    def _identity_values(userinfo, realm):
        """Return the template values for the authenticated subject.

        The client id is formed exactly as rest/session.py forms client.id, so the
        value used to filter ERMrest matches the id ERMrest records for the user.
        """
        claim_map = get_claim_map_for_realm(realm, current_app.config.get("IDP_CLAIM_MAPS"))
        iss = resolve_claim(userinfo, claim_map, "iss", userinfo.get("iss"))
        sub = resolve_claim(userinfo, claim_map, "sub", userinfo.get("sub"))
        if not sub:
            return {}
        return {"client_id": f"{iss}/{sub}" if iss else sub, "iss": iss or "", "sub": sub}

    def _remove_previous_entries(self, userinfo):
        previous = userinfo.pop(self.AUGMENTED_KEY, None) or {}
        for claim, ids in previous.items():
            existing = userinfo.get(claim)
            if not isinstance(existing, list):
                continue
            stale = set(ids)
            userinfo[claim] = [e for e in existing
                               if (e.get("id") if isinstance(e, dict) else e) not in stale]

    def _run_query(self, query, identity, auth, params):
        """Run one configured query; return its entries, or None on any failure."""
        name = query.get("name", "<unnamed>")
        url = query.get("url")
        id_template = query.get("id")
        claim = query.get("claim", "roles")
        if not url or not id_template:
            logger.warning("ERMrest role query '%s' requires both 'url' and 'id'; skipping.", name)
            return None
        if claim not in self.ALLOWED_CLAIMS:
            logger.warning("ERMrest role query '%s' has unsupported claim '%s'; skipping.", name, claim)
            return None

        try:
            url = self._render(url, identity, encode=True)
        except KeyError as e:
            logger.warning("ERMrest role query '%s' references unknown identity field %s; skipping.",
                           name, e)
            return None

        try:
            resp = requests.get(url,
                                headers={"Authorization": f"Bearer {auth}",
                                         "Accept": "application/json"},
                                timeout=params.get("ermrest_timeout", 5),
                                verify=not params.get("ermrest_bypass_cert_verify", False))
            resp.raise_for_status()
            rows = resp.json()
        except HTTPError as e:
            logger.warning("ERMrest role query '%s' failed with HTTP %s.", name, e.response.status_code)
            return None
        except Exception as e:
            logger.warning("ERMrest role query '%s' failed: %s", name, e)
            return None

        if not isinstance(rows, list):
            logger.warning("ERMrest role query '%s' did not return a list of rows.", name)
            return None

        display_template = query.get("display_name")
        entries = []
        for row in rows:
            try:
                ident = self._render(id_template, row)
                display_name = self._render(display_template, row) if display_template else ident
            except (KeyError, TypeError) as e:
                logger.debug("ERMrest role query '%s' row lacks column %s; skipping row.", name, e)
                continue
            entries.append({"id": ident, "display_name": display_name})
        return entries

    @classmethod
    def _render(cls, template, values, encode=False):
        """Substitute {name} placeholders from values.

        A missing or null value raises KeyError: a role id must never be rendered
        with a hole in it. With encode=True each value is percent-encoded so that
        it stays a single ERMrest path/filter literal.
        """
        def substitute(match):
            value = values.get(match.group(1))
            if value is None:
                raise KeyError(match.group(1))
            return quote(str(value), safe="") if encode else str(value)

        return cls.PLACEHOLDER.sub(substitute, template)


class RasDerivaErmrestSessionAugmentationProvider(RasSessionAugmentationProvider,
                                                  DerivaErmrestSessionAugmentationProvider):
    """RAS identity canonicalization combined with ERMrest role mapping.

    The two parents override disjoint extension points (build_identities and
    enrich_userinfo respectively), and DerivaErmrestSessionAugmentationProvider
    calls super().enrich_userinfo() first, so enrichment RAS adds later (e.g.
    GA4GH passport parsing) composes through the MRO without changes here.
    """
