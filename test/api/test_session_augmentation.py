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
import requests
from types import SimpleNamespace
from flask import g
from werkzeug.exceptions import HTTPException, NotFound, Forbidden
from credenza.api import util
from credenza.api.session.storage.session_store import SessionData
from credenza.api.session.augmentation import globus_provider
from credenza.api.session.augmentation.globus_provider import GlobusSessionAugmentationProvider
from credenza.api.session.augmentation.deriva_provider import DerivaSessionAugmentationProvider

# Fixed current time for deterministic ttl calculations
CUR_TIME = 1000


def make_token(scope, access_token, refresh_token=None, expires_in=None, resource_server=None):
    """
    Helper to build a token dict for get_additional_tokens.
    """
    token = {"scope": scope, "access_token": access_token}
    if refresh_token is not None:
        token["refresh_token"] = refresh_token
    if expires_in is not None:
        token["expires_in"] = expires_in
    if resource_server is not None:
        token["resource_server"] = resource_server
    return token

def expected_entry(access_token, refresh_token, expires_at, resource_server, last_refresh):
    """
    Build the expected entry in the additional_tokens map.
    """
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_at": expires_at,
        "resource_server": resource_server,
        "last_refresh_at": last_refresh,
        "refreshed_count": 0
    }

def test_with_list_input_single_scope(monkeypatch, app):
    tokens = [
        make_token(scope="read", access_token="at", refresh_token="rt", expires_in=10, resource_server="rs")
    ]
    # stub time.time to CUR_TIME
    import time as _time
    monkeypatch.setattr(_time, "time", lambda: CUR_TIME)
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
        result = provider.process_additional_tokens(tokens)
    assert result == {"read": expected_entry("at", "rt", CUR_TIME + 10, "rs", CUR_TIME)}


def test_process_additional_tokens_with_list_input_multiple_scopes_and_defaults(monkeypatch, app):
    tokens = [
        make_token(scope="x y", access_token="a", expires_in=5)
    ]
    import time as _time
    monkeypatch.setattr(_time, "time", lambda: CUR_TIME)
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
        result = provider.process_additional_tokens(tokens)
    assert result == {
        "x": expected_entry("a", None, CUR_TIME + 5, None, CUR_TIME),
        "y": expected_entry("a", None, CUR_TIME + 5, None, CUR_TIME)
    }


def test_process_additional_tokens_with_dict_input_other_and_dependent(monkeypatch, app):
    other = [make_token(scope="one", access_token="ot")]
    dependent = [make_token(scope="d1 d2", access_token="dt", refresh_token="drt", expires_in=20)]
    tokens_map = {"other_tokens": other, "dependent_tokens": dependent}
    import time as _time
    monkeypatch.setattr(_time, "time", lambda: CUR_TIME)
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
        result = provider.process_additional_tokens(tokens_map)
    assert result == {
        "one": expected_entry("ot", None, CUR_TIME + 0, None, CUR_TIME),
        "d1": expected_entry("dt", "drt", CUR_TIME + 20, None, CUR_TIME),
        "d2": expected_entry("dt", "drt", CUR_TIME + 20, None, CUR_TIME)
    }

@pytest.mark.parametrize("input_val", [None, {}, []])
def test_process_additional_tokens_with_empty_inputs(input_val, app):
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
        result = provider.process_additional_tokens(input_val)
    assert result == {}


def test_enrich_userinfo_non_globus(app):
    userinfo = {"iss": "https://other", "groups": ["existing"]}
    additional_tokens = {}
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
        result = provider.enrich_userinfo(userinfo, additional_tokens)
    assert result is False
    assert userinfo["groups"] == ["existing"]


def test_enrich_userinfo_globus_no_tokens(app):
    userinfo = {"iss": GlobusSessionAugmentationProvider.GLOBUS_ISSUER}
    additional_tokens = {}
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("globus")
        result = provider.enrich_userinfo(userinfo, additional_tokens)
    assert result is False
    assert "groups" not in userinfo


def test_enrich_userinfo_globus_request_exception(monkeypatch, app):
    userinfo = {"iss": GlobusSessionAugmentationProvider.GLOBUS_ISSUER, "email": "someone@example.org"}
    token_value = "bad_token"
    additional_tokens = {
        GlobusSessionAugmentationProvider.GLOBUS_GROUPS_SCOPE: {"access_token": token_value}
    }

    def raise_exception(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(requests, "get", raise_exception)

    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("globus")
        result = provider.enrich_userinfo(userinfo, additional_tokens)

    assert result is False
    assert "groups" not in userinfo


def test_enrich_userinfo_globus_invalid_response(monkeypatch, app):
    userinfo = {"iss": GlobusSessionAugmentationProvider.GLOBUS_ISSUER, "email": "u@example.org"}
    token_value = "some_token"
    additional_tokens = {
        GlobusSessionAugmentationProvider.GLOBUS_GROUPS_SCOPE: {"access_token": token_value}
    }

    # Simulate bad JSON structure (e.g. not a list)
    mock_resp = SimpleNamespace(
        status_code=200,
        json=lambda: {"not": "a list"},
        raise_for_status=lambda: None
    )

    monkeypatch.setattr(requests, "get", lambda *a, **k: mock_resp)

    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("globus")
        result = provider.enrich_userinfo(userinfo, additional_tokens)

    # Should raise but we catch all exceptions, so it just fails quietly
    assert result is False
    assert "groups" not in userinfo


def test_enrich_userinfo_globus_wrong_issuer(app):
    userinfo = {"iss": "https://not.globus.org", "email": "u@example.org"}
    additional_tokens = {
        GlobusSessionAugmentationProvider.GLOBUS_GROUPS_SCOPE: {"access_token": "t"}
    }
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("globus")
        result = provider.enrich_userinfo(userinfo, additional_tokens)

    assert result is False
    assert "groups" not in userinfo


def test_enrich_userinfo_globus_with_tokens(monkeypatch, app):
    userinfo = {"iss": GlobusSessionAugmentationProvider.GLOBUS_ISSUER, "groups": []}
    token_value = "grp_token"
    additional_tokens = {GlobusSessionAugmentationProvider.GLOBUS_GROUPS_SCOPE: {"access_token": token_value}}
    sample_groups = [{"id": "g1", "name": "Group One"}, {"id": "g2", "name": "Group Two"}]
    mock_resp = SimpleNamespace(status_code=200, json=lambda: sample_groups, raise_for_status=lambda: None)
    monkeypatch.setattr(requests, "get", lambda url, headers, timeout=None: mock_resp)
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("globus")
        provider.enrich_userinfo(userinfo, additional_tokens)
    assert isinstance(userinfo.get("groups"), list)
    assert len(userinfo["groups"]) == len(sample_groups)
    for g in sample_groups:
        assert any(item.get("display_name") == g["name"] for item in userinfo["groups"])


def test_fetch_dependent_tokens_not_globus(app):
    userinfo = {"iss": "https://other-issuer", "email": "u@example.com"}
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
        result = provider.fetch_dependent_tokens("unused_token", userinfo, scopes=["x"], access_type="offline")
    assert result == {}


def test_fetch_dependent_tokens_success(app, monkeypatch):
    stub_client = SimpleNamespace()
    calls = {}
    def fake_fetch(access_token, grant_type, scope, access_type):
        calls.update({"access_token": access_token, "grant_type": grant_type, "scope": scope, "access_type": access_type})
        return {"tok1": {"token": "abc"}}
    stub_client.fetch_dependent_tokens = fake_fetch
    factory = app.config["OIDC_CLIENT_FACTORY"]
    monkeypatch.setattr(factory, "get_client", lambda realm: stub_client)
    userinfo = {"iss": GlobusSessionAugmentationProvider.GLOBUS_ISSUER, "email": "u@example.com"}
    scopes = ["s1", "s2"]
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("globus")
        # patch process_additional_tokens since default is identity
        monkeypatch.setattr(provider, "process_additional_tokens", lambda tokens: {"wrapped": tokens})
        result = provider.fetch_dependent_tokens("access-token", userinfo, scopes=scopes, access_type="offline")
    assert calls["access_token"] == "access-token"
    assert calls["grant_type"] == GlobusSessionAugmentationProvider.GLOBUS_DEPENDENT_TOKEN_GRANT_TYPE
    assert calls["scope"] == scopes
    assert calls["access_type"] == "offline"
    assert result == {"wrapped": {"tok1": {"token": "abc"}}}


def test_fetch_dependent_tokens_failure(app, monkeypatch):
    stub_client = SimpleNamespace()
    stub_client.fetch_dependent_tokens = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("network down"))
    factory = app.config["OIDC_CLIENT_FACTORY"]
    monkeypatch.setattr(factory, "get_client", lambda realm: stub_client)
    userinfo = {"iss": GlobusSessionAugmentationProvider.GLOBUS_ISSUER, "email": "u@example.com"}
    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("test")
        result = provider.fetch_dependent_tokens("any-token", userinfo)
    assert result == {}

def test_fetch_dependent_tokens_non_globus_issuer(monkeypatch, app):
    userinfo = {
        "iss": "https://not.globus.org",
        "email": "u@example.org"
    }

    with app.app_context():
        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("globus")
        result = provider.fetch_dependent_tokens("any-token", userinfo)

    assert result == {}

def test_session_from_bearer_token(monkeypatch, app, store):
    with app.app_context():
        realm = app.config["DEFAULT_REALM"]
        client = app.config["OIDC_CLIENT_FACTORY"].get_client(realm)

        monkeypatch.setattr(store, "get_session_by_session_key", lambda at: (None, None))
        fake_claims = {"active": True, "iss": client.issuer, "aud": client.client_id,
                       "sub": "user1", "email": "user1@example.com",
                       "scope":"openid email profile","exp":9999999999}
        monkeypatch.setattr(client, "validate_access_token",
                            lambda token, required_audience, **kw: fake_claims)
        client.profile["accepted_scopes"] = [{"scope":"openid","issuer":client.issuer}]

        provider = app.config["SESSION_AUGMENTATION_PROVIDERS"].get("globus")
        monkeypatch.setattr(provider, "fetch_dependent_tokens",
                            lambda at, ui, scopes=None, access_type="online":
                            {"dep": {"refresh_token":"r","expires_at":123}})
        monkeypatch.setattr(provider, "process_additional_tokens", lambda tokens: {"wrapped":tokens})
        monkeypatch.setattr(provider, "enrich_userinfo", lambda ui, et: ui.update({"extra_group":"g3"}))

        audits = []
        monkeypatch.setattr(globus_provider, "audit_event", lambda event, **kw: audits.append((event, kw)))
        monkeypatch.setattr(util, "get_effective_scopes", lambda session_data: session_data.scopes)
        monkeypatch.setattr(store, "generate_session_id", lambda: "NEW_SESSION_ID")
        monkeypatch.setattr(store, "get_session_by_session_key", lambda sk: ("NEW_SESSION_ID", None))

        provider = util.get_augmentation_provider("globus")
        skey, sess = provider.session_from_bearer_token("token345")
        sid,_ = store.get_session_by_session_key(skey)
        assert skey == "token345"
        assert sid == "NEW_SESSION_ID"
        assert isinstance(sess, SessionData)
        assert sess.userinfo["extra_group"] == "g3"
        assert audits == [("session_from_bearer_token",
                           {"session_id":sid,
                            "user":"user1@example.com",
                            "sub":"user1",
                            "scopes": ["openid", "email", "profile", "dep"],
                            "realm":realm})]


def test_session_from_bearer_token_invalid(monkeypatch, app, store):
    with app.app_context():
        realm = app.config["DEFAULT_REALM"]
        client = app.config["OIDC_CLIENT_FACTORY"].get_client(realm)
        monkeypatch.setattr(store, "get_session_by_session_key", lambda at: (None, None))
        monkeypatch.setattr(client, "validate_access_token",
                            lambda token, **kw: (_ for _ in ()).throw(RuntimeError("token invalid")))
        client.profile["accepted_scopes"] = [{"scope":"openid","issuer":client.issuer}]
        with pytest.raises(NotFound):
            provider = util.get_augmentation_provider("globus")
            provider.session_from_bearer_token("bad-token")

def test_enrich_userinfo_deriva_success_bearer_token(monkeypatch, app):
    userinfo = {"email": "u@example.com"}
    sample_groups = [{"id": "g1", "name": "Group One"}, {"id": "g2", "name": "Group Two"}]
    config_patch = {
        "OIDC_IDP_PROFILES": {
            app.config["DEFAULT_REALM"]: {
                "session_augmentation_params": {
                    "groups_api_url": "https://example.org/api/groups"
                }
            }
        }
    }
    monkeypatch.setitem(app.config, "OIDC_IDP_PROFILES", config_patch["OIDC_IDP_PROFILES"])
    monkeypatch.setitem(app.config, "COOKIE_NAME", "mycookie")

    mock_resp = SimpleNamespace(
        status_code=200,
        json=lambda: {"groups": sample_groups},
        raise_for_status=lambda: None
    )

    monkeypatch.setattr(requests, "get", lambda url, headers, timeout, verify: mock_resp)

    with app.test_request_context():
        g.session_key = "my-token"
        provider = DerivaSessionAugmentationProvider()
        result = provider.enrich_userinfo(userinfo, {})

    assert result is True
    assert len(userinfo["groups"]) == 2
    assert userinfo["groups"][0]["display_name"] == "Group One"


def test_enrich_userinfo_deriva_missing_url(monkeypatch, app):
    from credenza.api.session.augmentation.deriva_provider import DerivaSessionAugmentationProvider
    userinfo = {"email": "u@example.com"}
    monkeypatch.setitem(app.config, "OIDC_IDP_PROFILES", {
        app.config["DEFAULT_REALM"]: {
            "session_augmentation_params": {
                # intentionally no groups_api_url
            }
        }
    })
    with app.app_context():
        provider = DerivaSessionAugmentationProvider()
        result = provider.enrich_userinfo(userinfo, {})
    assert result is False
    assert "groups" not in userinfo


def test_enrich_userinfo_deriva_http_401(monkeypatch, app):
    from credenza.api.session.augmentation.deriva_provider import DerivaSessionAugmentationProvider
    from requests.models import Response
    from requests import HTTPError

    userinfo = {"email": "u@example.com"}
    monkeypatch.setitem(app.config, "OIDC_IDP_PROFILES", {
        app.config["DEFAULT_REALM"]: {
            "session_augmentation_params": {
                "groups_api_url": "https://example.org/api/groups"
            }
        }
    })

    def raise_401():
        resp = Response()
        resp.status_code = 401
        raise HTTPError(response=resp)

    monkeypatch.setattr(requests, "get", lambda *a, **kw: raise_401())

    with app.test_request_context():
        g.session_key = "my-token"
        provider = DerivaSessionAugmentationProvider()
        result = provider.enrich_userinfo(userinfo, {})
    assert result is False


def test_enrich_userinfo_deriva_request_exception(monkeypatch, app):
    from credenza.api.session.augmentation.deriva_provider import DerivaSessionAugmentationProvider
    userinfo = {"email": "u@example.com"}
    monkeypatch.setitem(app.config, "OIDC_IDP_PROFILES", {
        app.config["DEFAULT_REALM"]: {
            "session_augmentation_params": {
                "groups_api_url": "https://example.org/api/groups"
            }
        }
    })
    monkeypatch.setattr(requests, "get", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("network fail")))

    with app.test_request_context():
        g.session_key = "any-token"
        provider = DerivaSessionAugmentationProvider()
        result = provider.enrich_userinfo(userinfo, {})
    assert result is False
