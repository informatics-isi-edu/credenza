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
from credenza.api.session.augmentation.ras_provider import RasSessionAugmentationProvider


FEDERATED_IAL2 = {
    "default_identity": "a3f92c61@login.gov",
    "authenticated_identity": "a3f92c61@login.gov",
    "sources": {
        "login.gov": {
            "identity_username": "a3f92c61@login.gov",
            "ial": 2,
            "identity_sub": "oj_ESe8qE",
        }
    },
    "identities": {
        "login.gov": {
            "mail": "fakey.mcfakerson@example.com",
            "userid": "a3f92c61",
            "firstname": "FAKEY",
            "lastname": "MCFAKERSON",
        }
    },
}


def test_ras_build_identities_from_ial2():
    provider = RasSessionAugmentationProvider()
    userinfo = {"federated_identities_ial2": FEDERATED_IAL2}

    idents = provider.build_identities(userinfo)

    assert len(idents) == 1
    # The id is the identity_username from the sources block (matching RAS's own
    # default_identity / authenticated_identity handle).
    assert "a3f92c61@login.gov" in idents
    ident = idents["a3f92c61@login.gov"]
    assert ident["sub"] == "oj_ESe8qE"
    assert ident["iss"] == "login.gov"
    assert ident["provider"] == "login.gov"
    assert ident["ial"] == 2
    assert ident["email"] == "fakey.mcfakerson@example.com"
    assert ident["userid"] == "a3f92c61"
    assert ident["name"] == "FAKEY MCFAKERSON"
    # build_identities is a pure transform: it does not mutate userinfo.
    assert "identities" not in userinfo


def test_ras_no_federated_identities_returns_empty():
    provider = RasSessionAugmentationProvider()
    userinfo = {"sub": "x", "email": "x@example.org"}

    assert provider.build_identities(userinfo) == {}


def test_ras_skips_source_without_identity_username():
    provider = RasSessionAugmentationProvider()
    userinfo = {
        "federated_identities_ial2": {
            "sources": {"login.gov": {"identity_sub": "s1", "ial": 2}},
            "identities": {"login.gov": {"mail": "m@example.org", "userid": "u1"}},
        }
    }

    assert provider.build_identities(userinfo) == {}


def test_ras_ial2_takes_precedence_over_non_ial2():
    provider = RasSessionAugmentationProvider()
    userinfo = {
        "federated_identities_ial2": {
            "sources": {"login.gov": {"identity_sub": "s1", "ial": 2,
                                      "identity_username": "u1@login.gov"}},
            "identities": {"login.gov": {"mail": "ial2@example.com", "userid": "u1"}},
        },
        "federated_identities": {
            "sources": {"login.gov": {"identity_sub": "s1", "ial": 1,
                                      "identity_username": "u1@login.gov"}},
            "identities": {"login.gov": {"mail": "ial1@example.com", "userid": "u1"}},
        },
    }

    idents = provider.build_identities(userinfo)

    assert len(idents) == 1
    ident = idents["u1@login.gov"]
    assert ident["ial"] == 2
    assert ident["email"] == "ial2@example.com"


def test_ras_multiple_sources():
    provider = RasSessionAugmentationProvider()
    userinfo = {
        "federated_identities_ial2": {
            "sources": {
                "login.gov": {"identity_sub": "s1", "ial": 2,
                              "identity_username": "u1@login.gov"},
                "era.nih.gov": {"identity_sub": "s2", "ial": 2,
                                "identity_username": "u2@era.nih.gov"},
            },
            "identities": {
                "login.gov": {"mail": "a@example.com", "userid": "u1"},
                "era.nih.gov": {"mail": "b@example.com", "userid": "u2"},
            },
        }
    }

    idents = provider.build_identities(userinfo)

    assert set(idents) == {"u1@login.gov", "u2@era.nih.gov"}
    assert idents["u2@era.nih.gov"]["email"] == "b@example.com"