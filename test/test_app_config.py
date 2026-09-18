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
import os

import pytest
from flask import Flask

from credenza.app import init_logging, load_config

VALID_KEY = "0123456789abcdef0123456789abcdef"
FILE_KEY = "fedcba9876543210fedcba9876543210"


@pytest.fixture
def config_root(tmp_path, monkeypatch):
    """Run load_config() in an isolated CWD with no ambient CREDENZA_* configuration.

    load_config() resolves its config and secrets paths relative to the working directory
    (the mod_wsgi daemon home in a deployment) and merges os.environ over any dotenv file,
    so both have to be neutralized for these tests to mean anything.
    """
    for key in [k for k in os.environ if k.startswith("CREDENZA_")]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("HOSTNAME", "credenza.example.org")
    (tmp_path / "config").mkdir()
    (tmp_path / "secrets").mkdir()
    monkeypatch.chdir(tmp_path)
    return tmp_path


def write_key_file(config_root, contents, path="secrets/encryption_key.json"):
    key_file = config_root / path
    key_file.parent.mkdir(parents=True, exist_ok=True)
    key_file.write_text(json.dumps(contents))
    return key_file


def load(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    app = Flask(__name__)
    load_config(app)
    return app


def test_encryption_disabled_ignores_key_file(config_root, monkeypatch):
    write_key_file(config_root, {"encryption_key": FILE_KEY})
    app = load(monkeypatch)
    assert app.config.get("ENCRYPT_SESSION_DATA") is False
    assert not app.config.get("ENCRYPTION_KEY")


def test_env_key_wins_over_key_file(config_root, monkeypatch):
    write_key_file(config_root, {"encryption_key": FILE_KEY})
    app = load(monkeypatch,
               CREDENZA_ENCRYPT_SESSION_DATA="true",
               CREDENZA_ENCRYPTION_KEY=VALID_KEY)
    assert app.config["ENCRYPTION_KEY"] == VALID_KEY


def test_key_file_used_when_env_key_unset(config_root, monkeypatch):
    write_key_file(config_root, {"encryption_key": FILE_KEY})
    app = load(monkeypatch, CREDENZA_ENCRYPT_SESSION_DATA="true")
    assert app.config["ENCRYPTION_KEY"] == FILE_KEY


def test_key_file_used_when_env_key_empty(config_root, monkeypatch):
    # An unsubstituted "${CREDENZA_ENCRYPTION_KEY}" placeholder in credenza.env interpolates
    # to the empty string, which must not count as a configured key.
    write_key_file(config_root, {"encryption_key": FILE_KEY})
    app = load(monkeypatch,
               CREDENZA_ENCRYPT_SESSION_DATA="true",
               CREDENZA_ENCRYPTION_KEY="")
    assert app.config["ENCRYPTION_KEY"] == FILE_KEY


def test_key_file_path_is_overridable(config_root, monkeypatch):
    write_key_file(config_root, {"encryption_key": FILE_KEY}, path="secrets/other_key.json")
    app = load(monkeypatch,
               CREDENZA_ENCRYPT_SESSION_DATA="true",
               CREDENZA_ENCRYPTION_KEY_FILE="secrets/other_key.json")
    assert app.config["ENCRYPTION_KEY"] == FILE_KEY


def test_missing_key_file_fails_closed(config_root, monkeypatch):
    with pytest.raises(ValueError, match="no encryption key is configured"):
        load(monkeypatch, CREDENZA_ENCRYPT_SESSION_DATA="true")


def test_overridden_key_file_missing_fails_closed(config_root, monkeypatch):
    write_key_file(config_root, {"encryption_key": FILE_KEY})
    with pytest.raises(ValueError, match="secrets/nonexistent.json"):
        load(monkeypatch,
             CREDENZA_ENCRYPT_SESSION_DATA="true",
             CREDENZA_ENCRYPTION_KEY_FILE="secrets/nonexistent.json")


def test_key_file_without_key_field_fails_closed(config_root, monkeypatch):
    write_key_file(config_root, {"not_the_key": FILE_KEY})
    with pytest.raises(ValueError, match="Missing or empty encryption_key"):
        load(monkeypatch, CREDENZA_ENCRYPT_SESSION_DATA="true")


def test_key_file_with_empty_key_fails_closed(config_root, monkeypatch):
    write_key_file(config_root, {"encryption_key": ""})
    with pytest.raises(ValueError, match="Missing or empty encryption_key"):
        load(monkeypatch, CREDENZA_ENCRYPT_SESSION_DATA="true")


def test_init_logging_is_idempotent(config_root, monkeypatch):
    # mod_wsgi retries a failed script import on every request, so create_app() can run
    # repeatedly in one process. Handlers must not accumulate, or each retry multiplies
    # every log line and buries the traceback that caused it.
    import logging

    credenza_logger = logging.getLogger("credenza")
    app = load(monkeypatch)
    init_logging(app)
    first = len(credenza_logger.handlers)
    for _ in range(5):
        init_logging(app)
    assert len(credenza_logger.handlers) == first
