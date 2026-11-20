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
from ..api.common.util import refresh_access_token, refresh_additional_tokens, reaugment_session
from ..api.session.storage.session_lock import session_lock
from ..telemetry import audit_event, audit_identity

logger = logging.getLogger(__name__)

def run_refresh_worker(app):
    store = app.config["SESSION_STORE"]
    interval = app.config.get("REFRESH_WORKER_POLL_INTERVAL", 60)
    debug_perf = app.config.get("DEBUG_PERF", False)

    while True:
        start = time.perf_counter()
        try:
            session_ids = store.list_session_ids()
            logger.debug(f"Checking {len(session_ids)} sessions for automatic refresh eligibility")

            for sid in session_ids:
                session = store.get_session_data(sid)
                if not session:
                    continue

                # For non-device sessions, don't allow refresh logic to handle session extension or token refresh
                if not session.is_device():
                    continue

                # Never wait: another thread holds this session's lock (a request extending it,
                # or a logout deleting it). Skip it this pass; the next pass picks it up.
                with session_lock(sid, blocking=False) as locked:
                    if not locked:
                        logger.debug(f"Session {sid} is locked by another thread; skipping this pass")
                        continue
                    token_refreshed = _refresh_session(app, store, sid)

                # Recompute roles and groups whenever the upstream token was refreshed, so changes
                # (e.g. a revoked grant) reach open device sessions on the refresh cycle. This runs
                # with the lock released: augmentation may query a resource server as the user,
                # and that server looks the session up with PUT /session, which takes the lock.
                if token_refreshed:
                    reaugment_session(sid, session.realm)

        except Exception:
            # pass-level guard: never let the thread die due to an unhandled exception
            logger.exception("Unhandled exception in refresh pass; continuing")

        elapsed_ms = int((time.perf_counter() - start) * 1000)
        if debug_perf:
            logger.debug(f"Refresh worker pass elapsed time: {elapsed_ms} ms")

        time.sleep(interval)


def _refresh_session(app, store, sid) -> bool:
    """Refresh one device session. The caller holds the session's lock.

    Returns True if the upstream access token was refreshed and the session written.
    """
    # Re-read under the lock: the copy read for the eligibility check may predate a refresh,
    # extension or delete by a request thread that has since released the lock.
    session = store.get_session_data(sid)
    if not session or not session.is_device():
        return False

    # A record whose key mapping is gone was deleted while a writer still held a copy, which wrote
    # it back. No key reaches it, so drop it rather than keep spending its refresh token upstream.
    if not store.get_session_key_for_session_id(sid):
        store.delete_session(sid)
        logger.warning(f"Deleted orphaned session record {sid} (no session key maps to it)")
        return False

    modified = False
    token_refreshed = False
    allow_auto_refresh = session.session_metadata.system.get("allow_automatic_refresh", False)
    prev_failures = session.session_metadata.system.get("refresh_failure_count", 0)

    # Refresh access tokens for sessions with automatic refresh allowed. refresh_access_token only
    # contacts the IdP when the token is due, judged on the copy just re-read.
    if session.refresh_token and allow_auto_refresh:
        token_refreshed = bool(refresh_access_token(sid, session))
        modified = token_refreshed or modified

    # Refresh other tokens if needed and allowed
    if allow_auto_refresh:
        modified = bool(refresh_additional_tokens(sid, session)) or modified

    # Give up on sessions whose upstream refresh keeps failing rather than
    # retrying a dead grant forever. Evict immediately on a terminal OAuth
    # error (e.g. invalid_grant), or after MAX_REFRESH_FAILURES consecutive
    # failures of any kind. The session must be re-established by re-auth.
    sys_meta = session.session_metadata.system
    failure_count = sys_meta.get("refresh_failure_count", 0)
    if failure_count > 0:
        terminal = sys_meta.get("last_refresh_error_terminal", False)
        max_failures = app.config.get("MAX_REFRESH_FAILURES", 5)
        if terminal or failure_count >= max_failures:
            identity = audit_identity(session.userinfo, session.realm)
            store.delete_session(sid)
            audit_event("session_evicted_refresh_failures",
                        session_id=sid,
                        **identity,
                        realm=session.realm,
                        failure_count=failure_count,
                        terminal=terminal,
                        last_error=sys_meta.get("last_refresh_error"))
            logger.warning(
                f"Evicted session {sid} for {identity['identity']} on realm {session.realm} after "
                f"{failure_count} refresh failure(s) (terminal={terminal}): "
                f"{sys_meta.get('last_refresh_error')}")
            return False

    # Enforce absolute cap after the refresh attempt so that a successful
    # token rotation (which updates absolute_expires_at) is not discarded.
    if store.enforce_absolute_cap(sid, session):
        return False

    # Persist on a successful token change, or when only the failure counter
    # advanced (so consecutive transient failures accumulate across passes).
    if modified or failure_count != prev_failures:
        _, written = store.update_session(sid, session)
        if written is None:
            return False
        if modified:
            audit_event("device_session_updated",
                        session_id=sid,
                        **audit_identity(session.userinfo, session.realm),
                        realm=session.realm)
    return token_refreshed
