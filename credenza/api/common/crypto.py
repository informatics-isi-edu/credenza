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
import json
import time
import base64
import logging
from typing import Dict, Optional, Callable
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

logger = logging.getLogger(__name__)


class AESGCMCodec:
    def __init__(self, key: str):
        if key is None:
            raise ValueError("Key is required")
        key_bytes = key.encode()
        if len(key_bytes) not in (16, 24, 32):
            raise ValueError(f"Key must be a 16, 24, or 32-byte UTF-8 string. Key length: {len(key_bytes)}")
        self.key = key_bytes

    def encrypt(self, plaintext: str) -> str:
        try:
            nonce = get_random_bytes(12)
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())

            data = {
                "nonce": base64.urlsafe_b64encode(nonce).decode(),
                "ciphertext": base64.urlsafe_b64encode(ciphertext).decode(),
                "tag": base64.urlsafe_b64encode(tag).decode()
            }
            return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise

    def decrypt(self, ciphertext: str) -> Optional[str]:
        try:
            data_json = base64.urlsafe_b64decode(ciphertext.encode()).decode()
            data = json.loads(data_json)

            nonce = base64.urlsafe_b64decode(data["nonce"])
            ciphertext = base64.urlsafe_b64decode(data["ciphertext"])
            tag = base64.urlsafe_b64decode(data["tag"])

            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode()
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return None

def generate_nonce():
  nonce = str(int(time.time())) + '.' + base64.urlsafe_b64encode(get_random_bytes(30)).decode() + '.'
  return nonce


_hasher_registry: Dict[str, Callable[[str, str], bool]] = {}

def register_hasher(name: str, fn: Callable[[str, str], bool]) -> None:
    _hasher_registry[name.lower()] = fn


def get_hasher(name: str) -> Optional[Callable[[str, str], bool]]:
    return _hasher_registry.get(name.lower())


def list_hashers():
    return list(_hasher_registry.keys())


def register_default_hashers() -> None:
    # Plain (always available)
    if "plain" not in _hasher_registry:
        def _plain(candidate: str, stored: str) -> bool:
            return candidate == stored
        register_hasher("plain", _plain)

    # bcrypt (optional)
    try:
        import bcrypt  # type: ignore
        if "bcrypt" not in _hasher_registry:
            def _bcrypt(candidate: str, stored: str) -> bool:
                if stored.startswith("bcrypt:"):
                    stored = stored.split(":", 1)[1]
                return bcrypt.checkpw(candidate.encode("utf-8"), stored.encode("utf-8"))
            register_hasher("bcrypt", _bcrypt)
            logger.debug("bcrypt hasher registered")
    except Exception: # pragma: no cover
        logger.debug("bcrypt hasher not available")

    # argon2 (optional)
    try:
        from argon2 import PasswordHasher  # type: ignore
        ph = PasswordHasher()
        if "argon2" not in _hasher_registry:
            def _argon2(candidate: str, stored: str) -> bool:
                if stored.startswith("argon2:"):
                    stored = stored.split(":", 1)[1]
                try:
                    return ph.verify(stored, candidate)
                except Exception:
                    return False
            register_hasher("argon2", _argon2)
            register_hasher("argon", _argon2)
            logger.debug("argon2 hasher registered")
    except Exception: # pragma: no cover
        logger.debug("argon2 hasher not available")


def verify_secret_candidate(candidate: str, *,
                            plaintext: Optional[str] = None,
                            stored_hash: Optional[str] = None,
                            scheme: Optional[str] = None) -> bool:
    if candidate is None:
        return False

    # Explicit scheme
    if scheme:
        hasher = get_hasher(scheme)
        if not hasher:
            logger.error("Secret verification scheme '%s' not registered", scheme)
            return False
        return hasher(candidate, stored_hash or "")

    # Auto-detect from stored_hash
    if stored_hash:
        lower = stored_hash.lower()

        # scheme-prefixed form: "scheme:rest"
        if ":" in stored_hash:
            scheme_hint, rest = stored_hash.split(":", 1)
            hasher = get_hasher(scheme_hint)
            if not hasher:
                logger.error("Secret verification scheme '%s' not registered", scheme_hint)
                return False
            return hasher(candidate, rest)

        # bcrypt shape
        if stored_hash.startswith("$2a$") or stored_hash.startswith("$2b$"):
            hasher = get_hasher("bcrypt")
            if not hasher:
                logger.error("bcrypt not registered but bcrypt hash encountered")
                return False
            return hasher(candidate, stored_hash)

        # argon2 shape
        if lower.startswith("$argon2"):
            hasher = get_hasher("argon2")
            if not hasher:
                logger.error("argon2 not registered but argon2 hash encountered")
                return False
            return hasher(candidate, stored_hash)

        # fallback raw equality
        return candidate == stored_hash

    if plaintext is not None:
        logger.warning("Using plaintext secret comparison — hashing recommended")
        return candidate == plaintext

    return False
