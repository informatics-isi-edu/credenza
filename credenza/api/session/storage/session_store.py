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
import uuid
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Dict, Any
from credenza.api.session.storage.backends.base import StorageBackend
from credenza.api.session.storage.backends.memory import MemoryBackend

logger = logging.getLogger(__name__)

@dataclass
class SessionMetadata:
    system: Dict[str, Any] = field(default_factory=dict)
    user: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class SessionData:
    id_token: str
    access_token: str
    refresh_token: str
    scopes: str
    userinfo: dict
    expires_at: float
    created_at: float
    updated_at: float
    realm: str
    session_metadata: SessionMetadata = field(default_factory=SessionMetadata)
    additional_tokens: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        result = asdict(self)
        result["session_metadata"] = asdict(self.session_metadata)
        return result

    @staticmethod
    def from_dict(data: dict) -> "SessionData":
        data["session_metadata"] = SessionMetadata(**data.get("session_metadata", {}))
        return SessionData(**data)


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
    def generate_session_key() -> str:
        return str(uuid.uuid4().hex)

    def _key(self, session_id):
        return f"{self.prefix}{self.sid_prefix}{session_id}"

    def map_session(self, session_key: str, session_id: str, ttl: int = None):
        """
        Store both directions of the mapping:
          skey:<session_key> -> session_id
          sid:<session_id> -> session_key
        """
        ttl = ttl if ttl is not None else self.ttl
        self.backend.setex(f"{self.prefix}{self.key_prefix}skey:{session_key}", session_id, ttl)
        self.backend.setex(f"{self.prefix}{self.key_prefix}sid:{session_id}", session_key, ttl)

    def unmap_session(self, session_id: str = None, session_key: str = None):
        if not (session_key or session_id):
            logger.debug("No session key or session id provided")

        # clean up both directions
        if not session_id:
            session_id = self.get_session_id_for_session_key(session_key)
        if not session_key:
            session_key = self.get_session_key_for_session_id(session_id)
        self.backend.delete(f"{self.prefix}{self.key_prefix}skey:{session_key}")
        self.backend.delete(f"{self.prefix}{self.key_prefix}sid:{session_id}")

    def get_session_id_for_session_key(self, session_key: str) -> str | None:
        val = self.backend.get(f"{self.prefix}{self.key_prefix}skey:{session_key}")
        if not val:
            return None
        return val.decode() if isinstance(val, bytes) else val

    def get_session_key_for_session_id(self, session_id: str) -> str | None:
        val = self.backend.get(f"{self.prefix}{self.key_prefix}sid:{session_id}")
        if not val:
            return None
        return val.decode() if isinstance(val, bytes) else val

    def create_session(self,
                       session_id,
                       access_token,
                       userinfo,
                       realm,
                       id_token = None,
                       refresh_token = None,
                       scopes = None,
                       metadata=None,
                       additional_tokens=None,
                       use_access_token_as_session_key=False) -> (SessionData, str):
        now = time.time()
        expires_at = now + self.ttl

        session_data = SessionData(
            id_token=id_token,
            access_token=access_token,
            refresh_token=refresh_token,
            scopes=scopes,
            userinfo=userinfo,
            expires_at=expires_at,
            created_at=now,
            updated_at=now,
            realm=realm,
            session_metadata=SessionMetadata(system=metadata or {}, user={}),
            additional_tokens=additional_tokens or {},
        )

        session_json = json.dumps(session_data.to_dict())
        if self.crypto_codec:
            session_json = self.crypto_codec.encrypt(session_json)

        session_key = access_token if use_access_token_as_session_key else self.generate_session_key()
        self.map_session(session_key, session_id)
        self.backend.setex(self._key(session_id), session_json, self.ttl)

        logger.debug(f"Created session {session_id} (realm={realm})")
        return session_key, session_data

    def get_session_data(self, session_id) -> SessionData | None:
        data = self.backend.get(self._key(session_id))
        if not data:
            return None
        try:
            if self.crypto_codec:
                data = self.crypto_codec.decrypt(data.decode())
                if data is None:
                    raise ValueError("Failed to decrypt data")
            return SessionData.from_dict(json.loads(data))
        except (ValueError, json.JSONDecodeError):
            self.backend.delete(self._key(session_id))
            logger.debug(f"Deleted corrupted or un-parseable session data for session {session_id}")
            return None

    def get_session_by_session_key(self, session_key) -> (str or None, SessionData or None):
        session_id = self.get_session_id_for_session_key(session_key)
        if not session_id:
            return None, None
        session = self.get_session_data(session_id)
        return session_id, session

    def update_session(self, session_id, session_data: SessionData):
        session_data.updated_at = time.time()
        session_data.expires_at = session_data.updated_at + self.ttl
        session_key = self.get_session_key_for_session_id(session_id)
        if self.crypto_codec:
            session_data = self.crypto_codec.encrypt(json.dumps(session_data.to_dict()))
        else:
            session_data = json.dumps(session_data.to_dict())

        self.map_session(session_key, session_id)
        self.backend.setex(self._key(session_id), session_data, self.ttl)

        logger.debug(f"Updated session {session_id}")

    def delete_session(self, session_id):
        session = self.get_session_data(session_id)
        if session:
            self.unmap_session(session_id)
        self.backend.delete(self._key(session_id))

        logger.debug(f"Deleted session {session_id}")

    def list_session_ids(self):
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

    def get_ttl(self, session_id):
        return self.backend.ttl(self._key(session_id))

    def tag_session_metadata(self, session_id: str, metadata: dict, scope: str = "system"):
        if scope not in ("user", "system"):
            raise ValueError("Metadata scope must be 'user' or 'system'")

        session = self.get_session_data(session_id)
        if not session:
            raise ValueError("Session not found")

        # Update metadata in appropriate scope
        target = getattr(session.session_metadata, scope)
        target.update(metadata)

        # Update timestamp
        session.updated_at = time.time()

        # Save updated session back as dict
        self.update_session(session_id, session)
        logger.debug(f"Tagged session {session_id} metadata[{scope}]: {metadata}")

    def store_nonce(self, state, nonce, ttl=600):
        self.backend.setex(f"{self.prefix}{self.oidc_prefix}nonce:{state}", nonce, ttl)

    def get_nonce(self, state):
        nonce = self.backend.get(f"{self.prefix}{self.oidc_prefix}nonce:{state}")
        if nonce:
            nonce = nonce.decode()
        return nonce

    def delete_nonce(self, state):
        self.backend.delete(f"{self.prefix}{self.oidc_prefix}nonce:{state}")

    def store_pkce_verifier(self, state: str, code_verifier: str, ttl: int = 600):
        self.backend.setex(f"{self.prefix}{self.oidc_prefix}pkce:{state}", code_verifier, ttl)

    def get_pkce_verifier(self, state: str) -> str | None:
        v = self.backend.get(f"{self.prefix}{self.oidc_prefix}pkce:{state}")
        if not v:
            return None
        return v.decode()

    def delete_pkce_verifier(self, state: str):
        self.backend.delete(f"{self.prefix}{self.oidc_prefix}pkce:{state}")

    def set_device_flow(self, device_code, flow_data, ttl):
        self.backend.setex(f"{self.prefix}{self.oidc_prefix}device_code:{device_code}", json.dumps(flow_data), ttl)

    def get_device_flow(self, device_code):
        flow_data = self.backend.get(f"{self.prefix}{self.oidc_prefix}device_code:{device_code}")
        if not flow_data:
            return None
        return json.loads(flow_data.decode())

    def get_device_flow_ttl(self, device_code):
        return self.backend.ttl(f"{self.prefix}{self.oidc_prefix}device_code:{device_code}")

    def delete_device_flow(self, device_code):
        self.backend.delete(f"{self.prefix}{self.oidc_prefix}device_code:{device_code}")

    def set_usercode_mapping(self, user_code, device_code, ttl):
        self.backend.setex(f"{self.prefix}{self.oidc_prefix}user_code:{user_code}", device_code, ttl)

    def get_device_code_for_usercode(self, user_code):
        code = self.backend.get(f"{self.prefix}{self.oidc_prefix}user_code:{user_code}")
        if code:
            return code.decode()
        return None

    def delete_usercode_mapping(self, user_code):
        self.backend.delete(f"{self.prefix}{self.oidc_prefix}user_code:{user_code}")
