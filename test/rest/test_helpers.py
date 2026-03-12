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
import uuid
from flask import jsonify, g
from credenza.api import common
from credenza.rest import helpers


def test_make_json_response_body_and_status():
    payload = {"msg": "ok"}
    res = helpers.make_json_response(payload)
    assert res.get_json() == payload
    assert res.mimetype == "application/json"


@pytest.mark.parametrize("host,config,expected", [
    ("app.example.org", "true", "example.org"),
    ("example.co.uk", "true", "example.co.uk"),
    ("localhost", "true", None),
    ("127.0.0.1", "true", None),
    ("sub.my.example.com", "true", "example.com"),
    ("app.example.org", "custom-domain.org", "custom-domain.org"),
    ("app.example.org", None, None),
    ("app.example.org", "false", None),
])
def test_get_cookie_domain(app, monkeypatch, host, config, expected):
    app.config["COOKIE_DOMAIN"] = config

    with app.test_request_context("/", base_url=f"http://{host}"):
        monkeypatch.setattr("flask.current_app", app)
        result = helpers.get_cookie_domain()
        assert result == expected


def test_client_ip_returns_remote_addr(app):
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "1.2.3.4"}):
        assert common.client_ip(helpers.request) == "1.2.3.4"


def test_client_ip_unknown_when_missing(app):
    with app.test_request_context("/", environ_base={}):
        assert common.client_ip(helpers.request) == "unknown"


def test_get_request_id_prefers_traceparent(app):
    with app.test_request_context("/", headers={"traceparent": "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"}):
        assert helpers.get_request_id(helpers.request.headers) == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


@pytest.mark.parametrize("header_name", ["X-Request-Id", "X-Request-ID", "x-request-id",
                                        "X-Correlation-Id", "X-Correlation-ID", "x-correlation-id",
                                        "X-Amzn-Trace-Id", "x-amzn-trace-id"])
def test_get_request_id_uses_common_headers(app, header_name):
    with app.test_request_context("/", headers={header_name: "RID-123"}):
        assert helpers.get_request_id(helpers.request.headers) == "RID-123"


def test_get_request_id_generates_uuid_last_resort(app, monkeypatch):
    monkeypatch.setattr(uuid, "uuid4", lambda: uuid.UUID("12345678-1234-5678-1234-567812345678"))
    with app.test_request_context("/", headers={}):
        assert helpers.get_request_id(helpers.request.headers) == "12345678-1234-5678-1234-567812345678"


def test_ip_rate_limited_allows_and_attaches_headers(app, monkeypatch):
    # Bucket that always allows
    class DummyBucket:
        def allow(self, key):
            return True, 7, 42  # allowed, remaining, reset_s

        def headers(self, remaining, reset_s):
            return {"X-RateLimit-Remaining": str(remaining), "X-RateLimit-Reset": str(reset_s)}

    # Ensure rate limits exist
    app.extensions.setdefault("rate_limits", {})
    app.extensions["rate_limits"]["30_per_min"] = DummyBucket()
    app.extensions["rate_limits"]["10_per_min"] = DummyBucket()

    # Stable client IP
    monkeypatch.setattr(common, "client_ip", lambda req: "1.2.3.4")

    @helpers.ip_rate_limited()
    def handler():
        # Ensure decorator stashed g.rate_limit
        assert "bucket" in g.rate_limit
        assert g.rate_limit["remaining"] == 7
        assert g.rate_limit["reset"] == 42
        return jsonify({"ok": True}), 200

    with app.test_request_context("/x", method="GET"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True}
        # Headers added by decorator
        assert resp.headers.get("X-RateLimit-Remaining") == "7"
        assert resp.headers.get("X-RateLimit-Reset") == "42"


def test_ip_rate_limited_denies_429_and_audits(app, monkeypatch):
    audit_events = []
    monkeypatch.setattr(helpers, "audit_event", lambda event, **kwargs: audit_events.append((event, kwargs)))

    class DenyBucket:
        def allow(self, key):
            return False, 0, 11

        def headers(self, remaining, reset_s):
            return {"X-RateLimit-Remaining": str(remaining), "X-RateLimit-Reset": str(reset_s)}

    app.extensions.setdefault("rate_limits", {})
    app.extensions["rate_limits"]["30_per_min"] = DenyBucket()
    app.extensions["rate_limits"]["10_per_min"] = DenyBucket()

    monkeypatch.setattr(helpers, "client_ip", lambda req: "9.9.9.9")

    @helpers.ip_rate_limited()
    def handler():
        return jsonify({"ok": True}), 200  # should never run

    with app.test_request_context("/x", method="POST"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 429
        data = resp.get_json()
        assert data["error"] == "rate_limited"
        assert "Too many requests:" in data["detail"]
        assert resp.headers.get("Retry-After") == "11"
        assert resp.headers.get("X-RateLimit-Remaining") == "0"
        assert resp.headers.get("X-RateLimit-Reset") == "11"

    assert any(ev == "request_rate_limited" for ev, _ in audit_events), audit_events

def test_ip_rate_limited_bypass_skips_limits_and_limit_or_429(app, monkeypatch):
    app.config["ENABLE_RATE_LIMITING"] = False

    # Make it obvious if the decorator tries to rate limit anyway
    app.extensions.pop("rate_limits", None)

    def boom(*args, **kwargs):
        raise AssertionError("limit_or_429 should not be called when ENABLE_RATE_LIMITING is False")

    monkeypatch.setattr(helpers, "limit_or_429", boom)

    @helpers.ip_rate_limited()
    def handler():
        return jsonify({"ok": True}), 200

    with app.test_request_context("/x", method="GET"):
        resp = app.make_response(handler())
        assert resp.status_code == 200
        assert resp.get_json() == {"ok": True}
        # Optional: ensure decorator didn't stash rate-limit info
        assert not hasattr(g, "rate_limit")


def test_perf_logged_noop_when_disabled(app):
    # Should not log anything or change return value
    app.config["DEBUG_PERF"] = False

    class DummyLogger:
        def __init__(self):
            self.debug_calls = []
            self.warning_calls = []

        def debug(self, msg):
            self.debug_calls.append(msg)

        def warning(self, msg):
            self.warning_calls.append(msg)

    log = DummyLogger()

    @helpers.perf_logged(warn_ms=1, logger=log)
    def handler():
        return ("ok", 200)

    with app.test_request_context("/p", method="GET"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 200
        assert resp.get_data(as_text=True) == "ok"

    assert log.debug_calls == []
    assert log.warning_calls == []


def test_perf_logged_debug_when_enabled_and_under_warn(app):
    app.config["DEBUG_PERF"] = True

    class DummyLogger:
        def __init__(self):
            self.debug_calls = []
            self.warning_calls = []

        def debug(self, msg):
            self.debug_calls.append(msg)

        def warning(self, msg):
            self.warning_calls.append(msg)

    log = DummyLogger()

    @helpers.perf_logged(warn_ms=10_000, logger=log)  # huge threshold => debug
    def handler():
        return ("ok", 200)

    with app.test_request_context("/p", method="GET"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 200

    assert len(log.debug_calls) == 1
    assert log.warning_calls == []
    assert "GET" in log.debug_calls[0]
    assert "took" in log.debug_calls[0]


def test_perf_logged_warning_when_enabled_and_over_warn(app, monkeypatch):
    app.config["DEBUG_PERF"] = True

    # Force perf_counter to simulate elapsed >= warn_ms
    seq = {"i": 0}

    def fake_perf_counter():
        seq["i"] += 1
        # first call start=0.0, second call end=1.0 => 1000ms
        return 0.0 if seq["i"] == 1 else 1.0

    monkeypatch.setattr(helpers.time, "perf_counter", fake_perf_counter)

    class DummyLogger:
        def __init__(self):
            self.debug_calls = []
            self.warning_calls = []

        def debug(self, msg):
            self.debug_calls.append(msg)

        def warning(self, msg):
            self.warning_calls.append(msg)

    log = DummyLogger()

    @helpers.perf_logged(warn_ms=500, logger=log)  # 1000ms >= 500 => warning
    def handler():
        return ("ok", 200)

    with app.test_request_context("/p", method="GET"):
        resp = handler()
        resp = app.make_response(resp)
        assert resp.status_code == 200

    assert log.debug_calls == []
    assert len(log.warning_calls) == 1
    assert "took" in log.warning_calls[0]



