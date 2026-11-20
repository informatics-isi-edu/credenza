#
# Copyright 2026 University of Southern California
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
from flask import Flask
from credenza.telemetry.audit import logger as audit_logger


def _capture(monkeypatch):
    records = []
    monkeypatch.setattr(audit_logger.logger, "info", lambda entry: records.append(entry))
    return records


def test_audit_event_records_user_agent_in_request_context(monkeypatch):
    records = _capture(monkeypatch)
    app = Flask(__name__)
    with app.test_request_context("/", headers={"User-Agent": "deriva-py/1.7"},
                                  environ_base={"REMOTE_ADDR": "1.2.3.4"}):
        audit_logger.audit_event("login", session_id="s1")
    assert records[0]["user_agent"] == "deriva-py/1.7"
    assert records[0]["client_ip"] == "1.2.3.4"


def test_audit_event_truncates_long_user_agent(monkeypatch):
    records = _capture(monkeypatch)
    app = Flask(__name__)
    with app.test_request_context("/", headers={"User-Agent": "x" * 5000}):
        audit_logger.audit_event("login")
    assert len(records[0]["user_agent"]) == audit_logger.MAX_USER_AGENT_LEN


def test_audit_event_omits_user_agent_without_request_or_header(monkeypatch):
    records = _capture(monkeypatch)
    audit_logger.audit_event("session_evicted_refresh_failures", session_id="s1")
    app = Flask(__name__)
    with app.test_request_context("/"):
        audit_logger.audit_event("login")
    assert "user_agent" not in records[0]
    assert "user_agent" not in records[1]
