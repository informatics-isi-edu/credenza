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
from ..api.util import refresh_access_token, refresh_additional_tokens, revoke_tokens
from ..telemetry import audit_event

logger = logging.getLogger(__name__)

def run_refresh_worker(app):
    store = app.config["SESSION_STORE"]
    profiles = app.config["OIDC_IDP_PROFILES"]
    interval = int(app.config.get("REFRESH_WORKER_POLL_INTERVAL", 60))
    session_expiry_threshold = int(app.config.get("SESSION_EXPIRY_THRESHOLD", 300))

    while True:
        now = time.time()
        session_ids = store.list_session_ids()
        logger.debug(f"Checking {len(session_ids)} sessions for refresh needs")

        for sid in session_ids:
            session = store.get_session_data(sid)
            if not session:
                continue

            realm = session.realm
            profile = profiles.get(realm)
            if not profile:
                logger.warning(f"No profile found for realm: {realm}")
                continue

            user = session.userinfo.get("email")
            sub = session.userinfo.get("sub")
            sys_metadata = session.session_metadata.system or {}
            refresh_expires_at = sys_metadata.get("refresh_expires_at")
            if refresh_expires_at and now > refresh_expires_at:
                audit_event("refresh_expired", session_id=sid)
                revoke_tokens(sid, session)
                store.delete_session(sid)
                continue

            # For non-device sessions, don't allow refresh logic to handle session extension or token refresh
            is_device_session = sys_metadata.get("device_session", False)
            if not is_device_session:
                continue

            modified = False
            allow_auto_refresh = session.session_metadata.system.get("allow_automatic_refresh", False)

            # Refresh access tokens for sessions with automatic refresh allowed
            if session.refresh_token and allow_auto_refresh:
                modified = refresh_access_token(sid, session)

            # Refresh other tokens if needed and allowed
            if allow_auto_refresh:
                modified = refresh_additional_tokens(sid, session)

            # Just bump session TTL if allowed and it is about to expire and hasn't otherwise been modified
            if not modified and allow_auto_refresh:
                ttl = store.get_ttl(sid)
                if 0 < ttl < session_expiry_threshold:
                    modified = True

            if modified:
                store.update_session(sid, session)
                audit_event("device_session_extended", session_id=sid, user=user, sub=sub, realm=realm)

        time.sleep(interval)
