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
import enum
import uuid
import json
import hashlib
import secrets
import logging
from dataclasses import dataclass, field, asdict
from typing import Any, Optional, Tuple
from .backends.base import StorageBackend
from .backends.memory import MemoryBackend
from ....telemetry import audit_event

logger = logging.getLogger(__name__)

TRANSIENT_DATA_TTL = 900
PENDING_CONSENT_TTL = 300       # 5 minutes
CONSENT_DEFAULT_TTL = 7776000   # 90 days
SESSION_DEFAULT_ABSOLUTE_LIFETIME_SECONDS = 86400  # 24 hours

class SessionType(str, enum.Enum):
    USER = "user"
    DEVICE = "device"
    DERIVED = "derived"
    SERVICE = "service"

@dataclass
class SessionMetadata:
    system: dict[str, Any] = field(default_factory=dict)
    user: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Coerce None -> {} and reject non-dict
        if self.system is None:
            self.system = {}
        if self.user is None:
            self.user = {}
        if not isinstance(self.system, dict):
            raise ValueError("session_metadata.system must be a dict")
        if not isinstance(self.user, dict):
            raise ValueError("session_metadata.user must be a dict")

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionData:
    access_token: str
    userinfo: dict
    created_at: int
    updated_at: int
    expires_at: int
    realm: str
    _session_type: SessionType = field(repr=False) # read only
    _allowed_resources: list[str] = field(default_factory=list) # read only
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    scopes: Optional[str] = None
    session_ttl: Optional[int] = None
    absolute_expires_at: Optional[int] = None
    session_metadata: SessionMetadata = field(default_factory=SessionMetadata)
    additional_tokens: dict = field(default_factory=dict)

    @property
    def session_type(self) -> SessionType:
        return self._session_type

    @property
    def allowed_resources(self) -> list[str]:
        return self._allowed_resources

    def to_dict(self) -> dict:
        result = asdict(self)
        result["session_metadata"] = asdict(self.session_metadata)
        return result

    @staticmethod
    def from_dict(data: dict) -> "SessionData":
        md = data.get("session_metadata")
        if md is None:
            md = {}
        if not isinstance(md, dict):
            raise ValueError("session_metadata must be an object")
        data["session_metadata"] = SessionMetadata(**md)
        return SessionData(**data)

    def is_primary(self) -> bool:
        return self.session_type in {SessionType.USER, SessionType.DEVICE}

    def is_derived(self) -> bool:
        return self.session_type == SessionType.DERIVED

    def is_device(self) -> bool:
        return self.session_type == SessionType.DEVICE

    def is_service(self) -> bool:
        return self.session_type == SessionType.SERVICE

    def can_extend(self) -> bool:
        return self.session_type in {SessionType.USER, SessionType.DEVICE}

    def can_refresh_upstream(self) -> bool:
        return self.session_type == SessionType.DEVICE


class SessionStore:
    def __init__(self, backend: StorageBackend = MemoryBackend(), ttl=2100, crypto_codec=None):
        self.backend = backend
        self.ttl = ttl
        self.prefix = "credenza:"
        self.sid_prefix = "session:"
        self.key_prefix = "keymap:"
        self.oidc_prefix = "oidc:"
        self.crypto_codec = crypto_codec

    @staticmethod
    def generate_session_id() -> str:
        return str(uuid.uuid4())

    @staticmethod
    def generate_session_key(nbytes: int = 32) -> str:
        """
        Generate a URL-safe, base64-like secret token with `nbytes` of entropy, suitable for cookies / bearer tokens.
        Default nbytes=32 => 256 bits of entropy.
        """
        return secrets.token_urlsafe(nbytes)

    def _key(self, session_id) -> str:
        return f"{self.prefix}{self.sid_prefix}{session_id}"

    def map_session(self, session_key: str, session_id: str, ttl: int = None) -> None:
        """
        Store both directions of the mapping:
          skey:<session_key> -> session_id
          sid:<session_id> -> session_key
        """
        ttl = ttl if ttl is not None else self.ttl
        self.backend.setex(f"{self.prefix}{self.key_prefix}skey:{session_key}", session_id, ttl)
        self.backend.setex(f"{self.prefix}{self.key_prefix}sid:{session_id}", session_key, ttl)

    def unmap_session(self, session_id: str = None, session_key: str = None) -> None:
        if not (session_key or session_id):
            logger.debug("No session key or session id provided")
            return

        if session_id is None and session_key is not None:
            session_id = self.get_session_id_for_session_key(session_key)

        if session_key is None and session_id is not None:
            session_key = self.get_session_key_for_session_id(session_id)

        if session_key:
            self.backend.delete(f"{self.prefix}{self.key_prefix}skey:{session_key}")
        if session_id:
            self.backend.delete(f"{self.prefix}{self.key_prefix}sid:{session_id}")

    def get_session_id_for_session_key(self, session_key: str) -> Optional[str]:
        val = self.backend.get(f"{self.prefix}{self.key_prefix}skey:{session_key}")
        if not val:
            return None
        return val.decode() if isinstance(val, bytes) else val

    def get_session_key_for_session_id(self, session_id: str) -> Optional[str]:
        val = self.backend.get(f"{self.prefix}{self.key_prefix}sid:{session_id}")
        if not val:
            return None
        return val.decode() if isinstance(val, bytes) else val

    def create_session(self,
                       session_id,
                       session_type,
                       access_token,
                       userinfo,
                       realm,
                       allowed_resources = None,
                       id_token = None,
                       refresh_token = None,
                       scopes = None,
                       metadata=None,
                       additional_tokens=None,
                       use_access_token_as_session_key=False,
                       expires_at=None,
                       session_ttl=None,
                       absolute_session_lifetime_secs=None) -> tuple[Optional[str], Optional[SessionData]]:
        if session_type is None:
            raise ValueError("session_type is required")

        now = int(time.time())
        ttl = self.ttl if session_ttl is None else int(session_ttl)
        if expires_at is None:
            expires_at = (now + ttl)
        if absolute_session_lifetime_secs is not None:
            absolute_expires_at = now + absolute_session_lifetime_secs
        else:
            absolute_expires_at = now + SESSION_DEFAULT_ABSOLUTE_LIFETIME_SECONDS

        sys_md = {} if metadata is None else metadata
        if not isinstance(sys_md, dict):
            raise ValueError("metadata must be a dict")
        session_metadata = SessionMetadata(system=sys_md, user={})

        session_data = SessionData(
            id_token=id_token,
            access_token=access_token,
            refresh_token=refresh_token,
            scopes=scopes,
            userinfo=userinfo,
            expires_at=expires_at,
            absolute_expires_at=absolute_expires_at,
            created_at=now,
            updated_at=now,
            realm=realm,
            _session_type=session_type,
            _allowed_resources=allowed_resources,
            session_ttl=ttl,
            session_metadata=session_metadata,
            additional_tokens=additional_tokens or {},
        )

        session_json = json.dumps(session_data.to_dict(), separators=(",", ":"))
        if self.crypto_codec:
            session_json = self.crypto_codec.encrypt(session_json)

        session_key = access_token if use_access_token_as_session_key else self.generate_session_key()
        ttl = int(expires_at - now)
        if ttl < 0:
            ttl = 0
        self.map_session(session_key, session_id, ttl)
        self.backend.setex(self._key(session_id), session_json, ttl)

        logger.debug(f"Created session {session_id} (realm={realm})")
        return session_key, session_data

    def _decode_backend_value(self, input_data: Any) -> Optional[str]:
        if input_data is None:
            return None
        if isinstance(input_data, (bytes, bytearray)):
            input_str = input_data.decode("utf-8")
        elif isinstance(input_data, str):
            input_str = input_data
        else:
            raise ValueError(f"Unexpected backend value type: {type(input_data)!r}")

        if self.crypto_codec:
            input_str = self.crypto_codec.decrypt(input_str)
            if input_str is None:
                raise ValueError("Failed to decrypt data")

        return input_str

    def get_session_data(self, session_id) -> Optional[SessionData]:
        backend_value = self.backend.get(self._key(session_id))
        if not backend_value:
            return None
        try:
            input_str = self._decode_backend_value(backend_value)
            return SessionData.from_dict(json.loads(input_str))
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as e:
            self.backend.delete(self._key(session_id))
            logger.debug("Deleted corrupted/unparseable session %s: %s", session_id, e)
            return None

    def get_session_by_session_key(self, session_key) -> tuple[Optional[str], Optional[SessionData]]:
        session_id = self.get_session_id_for_session_key(session_key)
        if not session_id:
            return None, None
        session = self.get_session_data(session_id)
        return session_id, session

    def get_active_session_by_session_id(self, sid: str) -> Optional[SessionData]:
        """
        Retrieve only an `active` session by enforcing absolute cap (delete if expired).
        Returns session or None if session expired or missing.
        """
        session = self.get_session_data(sid)
        if session is None:
            return None

        cap = session.absolute_expires_at
        now = int(time.time())
        if cap is not None and now >= int(cap):
            try:
                self.delete_session(sid)
                audit_event("session_deleted_absolute_lifetime_expired",
                            session_id=sid,
                            realm=session.realm,
                            sub=session.userinfo.get("sub"),
                            absolute_expires_at=cap)
            except Exception:
                logger.exception(f"failed deleting session after absolute expiry for sid={sid}")
            return None

        return session

    def get_active_session_by_session_key(self, skey: str) -> Tuple[Optional[str], Optional[SessionData]]:
        sid = self.get_session_id_for_session_key(skey)
        if not sid:
            return None, None

        return sid, self.get_active_session_by_session_id(sid)

    def update_session(self, session_id, session_data: SessionData) -> tuple[Optional[str], Optional[SessionData]]:
        now = int(time.time())
        session_data.updated_at = now

        # Extend expires_at unless session_ttl is 0; if session_ttl is None, use store default ttl
        if session_data.session_ttl is not None:
            if session_data.session_ttl > 0 and session_data.expires_at < (now + session_data.session_ttl):
                session_data.expires_at = (now + session_data.session_ttl)
        else:
            if session_data.expires_at < (now + self.ttl):
                session_data.expires_at = (now + self.ttl)
        ttl = int(session_data.expires_at - now)
        if ttl < 0:
            ttl = 0

        session_key = self.get_session_key_for_session_id(session_id)
        if not session_key:
            # mapping missing
            logger.warning("Missing session key mapping for session_id=%s; not remapping", session_id)
        else:
            self.map_session(session_key, session_id, ttl)

        if self.crypto_codec:
            session_json = self.crypto_codec.encrypt(json.dumps(session_data.to_dict(), separators=(",", ":")))
        else:
            session_json = json.dumps(session_data.to_dict(), separators=(",", ":"))

        self.backend.setex(self._key(session_id), session_json, ttl)

        logger.debug(f"Updated session {session_id}")
        return session_key, session_data

    def delete_session(self, session_id) -> None:
        session_key = self.get_session_key_for_session_id(session_id)
        self.unmap_session(session_id=session_id, session_key=session_key)
        self.backend.delete(self._key(session_id))

        logger.debug(f"Deleted session {session_id}")

    def list_session_ids(self) -> list[str]:
        base = f"{self.prefix}{self.sid_prefix}"
        ids = []
        for val in self.backend.scan_iter(f"{base}*"):
            # decode bytes -> str if necessary
            key = val.decode() if isinstance(val, (bytes, bytearray)) else val

            if not key.startswith(base):
                continue
            # strip off the prefix entirely
            sid = key[len(base):]
            # strip leading ":" if necessary
            if sid.startswith(":"):
                sid = sid[1:]

            ids.append(sid)

        return ids

    def get_ttl(self, session_id) -> int:
        return self.backend.ttl(self._key(session_id))

    def tag_session_metadata(self, session_id: str, metadata: dict, scope: str = "system") -> None:
        if scope not in ("user", "system"):
            raise ValueError("Metadata scope must be 'user' or 'system'")

        session = self.get_session_data(session_id)
        if not session:
            raise ValueError("Session not found")

        # Update metadata in appropriate scope
        target = getattr(session.session_metadata, scope)
        target.update(metadata)

        # Save updated session back as dict
        self.update_session(session_id, session)
        logger.debug(f"Tagged session {session_id} metadata[{scope}]: {metadata}")

    def set_authn_request_ctx(self, state, authn_request_ctx, ttl=TRANSIENT_DATA_TTL) -> None:
        ctx = json.dumps(authn_request_ctx, separators=(",", ":"))
        if self.crypto_codec:
            ctx = self.crypto_codec.encrypt(ctx)

        self.backend.setex(f"{self.prefix}{self.oidc_prefix}authn_request_ctx:{state}", ctx, ttl)

    def get_authn_request_ctx(self, state) -> Any:
        authn_request_ctx = self._decode_backend_value(
            self.backend.get(f"{self.prefix}{self.oidc_prefix}authn_request_ctx:{state}"))
        if not authn_request_ctx:
            return None

        return json.loads(authn_request_ctx)

    def delete_authn_request_ctx(self, state) -> None:
        self.backend.delete(f"{self.prefix}{self.oidc_prefix}authn_request_ctx:{state}")

    def set_device_flow(self, device_code, flow_data, ttl) -> None:
        data = json.dumps(flow_data, separators=(",", ":"))
        if self.crypto_codec:
            data = self.crypto_codec.encrypt(data)

        self.backend.setex(f"{self.prefix}{self.oidc_prefix}device_code:{device_code}", data, ttl)

    def get_device_flow(self, device_code) -> Any:
        flow_data = self._decode_backend_value(
            self.backend.get(f"{self.prefix}{self.oidc_prefix}device_code:{device_code}"))
        if not flow_data:
            return None

        return json.loads(flow_data)

    def get_device_flow_ttl(self, device_code) -> int:
        return self.backend.ttl(f"{self.prefix}{self.oidc_prefix}device_code:{device_code}")

    def delete_device_flow(self, device_code) -> None:
        self.backend.delete(f"{self.prefix}{self.oidc_prefix}device_code:{device_code}")

    def set_usercode_mapping(self, user_code, device_code, ttl) -> None:
        if self.crypto_codec:
            device_code = self.crypto_codec.encrypt(device_code)

        self.backend.setex(f"{self.prefix}{self.oidc_prefix}user_code:{user_code}", device_code, ttl)

    def consume_usercode_mapping(self, user_code) -> Optional[str]:
        key = f"{self.prefix}{self.oidc_prefix}user_code:{user_code}"

        return self._decode_backend_value(self.backend.consume(key))

    def delete_usercode_mapping(self, user_code) -> None:
        self.backend.delete(f"{self.prefix}{self.oidc_prefix}user_code:{user_code}")

    def set_authorization_code(self, code: str, payload: dict, ttl: int = 300) -> None:
        data = json.dumps(payload, separators=(",", ":"))
        if self.crypto_codec:
            data = self.crypto_codec.encrypt(data)

        self.backend.setex(f"{self.prefix}{self.oidc_prefix}authz_code:{code}", data, ttl)

    def consume_authorization_code(self, code: str) -> Any:
        key = f"{self.prefix}{self.oidc_prefix}authz_code:{code}"
        code_data = self._decode_backend_value(self.backend.consume(key))
        if code_data is None:
            return None

        return json.loads(code_data)

    # ------------------------------------------------------------------
    # Consent store operations (ADR-0002)
    # ------------------------------------------------------------------
    # Pending consent keys use a random token; consent record keys are
    # SHA-256 hashes of the principal + client/resource composite to
    # safely handle arbitrary URIs and iss/sub values.

    def _pending_consent_key(self, token: str) -> str:
        return f"{self.prefix}consent:pending:{token}"

    def _consent_auth_key(self, principal: str, client_id: str) -> str:
        h = hashlib.sha256(f"auth\x00{principal}\x00{client_id}".encode()).hexdigest()
        return f"{self.prefix}consent:auth:{h}"

    def _consent_deleg_key(self, principal: str, rs_resource: str) -> str:
        h = hashlib.sha256(f"deleg\x00{principal}\x00{rs_resource}".encode()).hexdigest()
        return f"{self.prefix}consent:deleg:{h}"

    def set_pending_consent(self, token: str, data: dict, ttl: int = PENDING_CONSENT_TTL) -> None:
        serialized = json.dumps(data, separators=(",", ":"))
        if self.crypto_codec:
            serialized = self.crypto_codec.encrypt(serialized)
        self.backend.setex(self._pending_consent_key(token), serialized, ttl)

    def get_pending_consent(self, token: str) -> Optional[dict]:
        val = self._decode_backend_value(self.backend.get(self._pending_consent_key(token)))
        if not val:
            return None
        return json.loads(val)

    def get_and_consume_pending_consent(self, token: str) -> Optional[dict]:
        val = self._decode_backend_value(self.backend.consume(self._pending_consent_key(token)))
        if not val:
            return None
        return json.loads(val)

    def set_consent_auth(self, principal: str, client_id: str, ttl: int = CONSENT_DEFAULT_TTL) -> None:
        self.backend.setex(self._consent_auth_key(principal, client_id), "1", ttl)

    def get_consent_auth(self, principal: str, client_id: str) -> Optional[str]:
        return self._decode_backend_value(self.backend.get(self._consent_auth_key(principal, client_id)))

    def set_consent_deleg(self, principal: str, rs_resource: str, ttl: int = CONSENT_DEFAULT_TTL) -> None:
        self.backend.setex(self._consent_deleg_key(principal, rs_resource), "1", ttl)

    def get_consent_deleg(self, principal: str, rs_resource: str) -> Optional[str]:
        return self._decode_backend_value(self.backend.get(self._consent_deleg_key(principal, rs_resource)))
