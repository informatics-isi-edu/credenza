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
import pytest
import json
import base64
import importlib.util
from credenza.api.common import crypto


@pytest.fixture
def isolate_hasher_registry():
    """Snapshot and restore the global hasher registry for tests that mutate it."""
    before = dict(crypto._hasher_registry)
    try:
        yield
    finally:
        crypto._hasher_registry.clear()
        crypto._hasher_registry.update(before)


def test_decrypt_invalid_ciphertext_returns_none():
    codec = crypto.AESGCMCodec("supersecretvalue")
    assert codec.decrypt("not-a-valid-token") is None


def test_decrypt_tampered_ciphertext_returns_none():
    codec = crypto.AESGCMCodec("supersecretvalue")
    plaintext = json.dumps({"k": "v"})

    token = codec.encrypt(plaintext)

    # Outer layer is base64(urlsafe) encoded JSON bytes
    raw = base64.urlsafe_b64decode(token.encode())
    assert raw, "expected non-empty decoded payload"

    # Flip one byte deterministically (not the first/last to avoid trivial decode issues)
    b = bytearray(raw)
    idx = min(5, len(b) - 1)
    b[idx] ^= 0x01
    tampered = base64.urlsafe_b64encode(bytes(b)).decode()

    # GCM integrity should fail => decrypt() returns None
    assert codec.decrypt(tampered) is None


def test_encrypt_decrypt_roundtrip():
    codec = crypto.AESGCMCodec("supersecretvalue")
    plaintext = {"key": "value"}
    encrypted = codec.encrypt(json.dumps(plaintext))
    decrypted = json.loads(codec.decrypt(encrypted))
    assert decrypted["key"] == "value"


def test_generate_nonce_length_and_uniqueness():
    n1 = crypto.generate_nonce()
    n2 = crypto.generate_nonce()
    assert isinstance(n1, str) and len(n1) >= 32
    assert isinstance(n2, str) and n1 != n2
    n1 = crypto.generate_nonce()
    n2 = crypto.generate_nonce()
    assert isinstance(n1, str) and len(n1) >= 32
    assert isinstance(n2, str) and n1 != n2


def test_register_default_hashers_and_plain_verification(isolate_hasher_registry):
    # Ensure default hashers are registered (will register 'plain' at minimum)
    crypto.register_default_hashers()
    hashers = crypto.list_hashers()
    assert "plain" in hashers

    # Plaintext comparison via plaintext param
    assert crypto.verify_secret_candidate("secret", plaintext="secret") is True

    # Plaintext comparison via stored_hash fallback (no scheme)
    assert crypto.verify_secret_candidate("secret", stored_hash="secret") is True


def test_register_and_use_custom_scheme_hasher(isolate_hasher_registry):
    # Register a custom scheme that expects "prefix_value" as stored form and returns True only for that
    called = {"seen": False}

    def dummy_hasher(candidate: str, stored: str) -> bool:
        called["seen"] = True
        # stored will be the "rest" portion after splitting "testscheme:rest"
        return candidate == "cand" and stored == "rest"

    crypto.register_hasher("testscheme", dummy_hasher)
    assert "testscheme" in crypto.list_hashers()

    # Stored form with scheme prefix should invoke the registered hasher
    assert crypto.verify_secret_candidate("cand", stored_hash="testscheme:rest") is True
    assert called["seen"] is True

def test_verify_secret_candidate_with_explicit_scheme_success(isolate_hasher_registry):
    called = {"seen": False}

    def dummy(candidate: str, stored: str) -> bool:
        called["seen"] = True
        return candidate == "abc" and stored == "xyz"

    crypto.register_hasher("myscheme", dummy)

    # Explicit scheme should invoke dummy directly
    assert crypto.verify_secret_candidate(
        "abc",
        stored_hash="xyz",
        scheme="myscheme"
    ) is True

    assert called["seen"] is True


def test_verify_secret_candidate_with_explicit_scheme_missing(isolate_hasher_registry):
    # No hasher registered for this scheme
    assert crypto.verify_secret_candidate(
        "abc",
        stored_hash="xyz",
        scheme="doesnotexist"
    ) is False


def test_get_hasher_case_insensitive(isolate_hasher_registry):
    def noop(candidate: str, stored: str) -> bool:
        return False

    crypto.register_hasher("MyScheme", noop)
    # lookup should be case-insensitive
    assert crypto.get_hasher("myscheme") is noop
    assert "myscheme" in crypto.list_hashers()


@pytest.mark.skipif(importlib.util.find_spec("bcrypt") is None, reason="bcrypt not available")
def test_bcrypt_verification_if_available(isolate_hasher_registry):
    # bcrypt path: create a bcrypt hash and verify via verify_secret_candidate
    import bcrypt
    crypto.register_default_hashers()
    pw = b"testpw"
    hashed = bcrypt.hashpw(pw, bcrypt.gensalt()).decode("utf-8")
    # stored form may be scheme-prefixed or raw bcrypt string; both are handled by verify_secret_candidate
    assert crypto.verify_secret_candidate("testpw", stored_hash=f"bcrypt:{hashed}") is True
    assert crypto.verify_secret_candidate("testpw", stored_hash=hashed) is True


@pytest.mark.skipif(importlib.util.find_spec("argon2") is None, reason="argon2 not available")
def test_argon2_verification_if_available(isolate_hasher_registry):
    # argon2 path: create an argon2 hash and verify via verify_secret_candidate
    from argon2 import PasswordHasher
    crypto.register_default_hashers()
    ph = PasswordHasher()
    h = ph.hash("s3cr3t")
    # verify_secret_candidate handles stored hash shapes that start with "$argon2" or scheme-prefixed "argon2:..."
    assert crypto.verify_secret_candidate("s3cr3t", stored_hash=h) is True
    assert crypto.verify_secret_candidate("s3cr3t", stored_hash=f"argon2:{h}") is True
