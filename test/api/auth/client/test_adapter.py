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
from typing import Dict, Any
from credenza.api.auth.client.adapters import adapter as ad_mod


def _make_config(adapter_name: str) -> ad_mod.AdapterConfig:
    """Helper: create a minimal AdapterConfig instance for tests."""
    return ad_mod.AdapterConfig(
        client_id="cid",
        adapter_name=adapter_name,
        config_dict={},
    )


def test_init_subclass_requires_adapter_name_and_supported_methods():
    # Missing ADAPTER_NAME should raise at class definition time
    with pytest.raises(TypeError, match="must define ADAPTER_NAME"):
        class BrokenAdapter1(ad_mod.AdapterInterface):
            SUPPORTED_AUTH_METHODS = ("method",)

    # Missing SUPPORTED_AUTH_METHODS should raise at class definition time
    with pytest.raises(TypeError, match="must define SUPPORTED_AUTH_METHODS"):
        class BrokenAdapter2(ad_mod.AdapterInterface):
            ADAPTER_NAME = "broken2"

    # Invalid SUPPORTED_AUTH_METHODS type should raise
    with pytest.raises(TypeError, match="SUPPORTED_AUTH_METHODS must be a tuple"):
        class BrokenAdapter3(ad_mod.AdapterInterface):
            ADAPTER_NAME = "broken3"
            SUPPORTED_AUTH_METHODS = ["not", "a", "tuple"]


def test_supported_auth_methods_normalize_and_dedupe():
    # Define adapter with mixed-case and duplicate methods
    class NormalizingAdapter(ad_mod.AdapterInterface):
        ADAPTER_NAME = "norm"
        SUPPORTED_AUTH_METHODS = ("Client_Secret_Basic", "client_secret_basic", "OTHER")

        @classmethod
        def from_dict(cls, config: Dict[str, Any], client_id: str):
            return cls(_make_config(cls.ADAPTER_NAME))

        def authenticate(self, proof_context, allowed_methods=None):
            raise NotImplementedError()

    # After class creation SUPPORTED_AUTH_METHODS should be normalized (lowercase) and deduped
    assert isinstance(NormalizingAdapter.SUPPORTED_AUTH_METHODS, tuple)
    assert "client_secret_basic" in NormalizingAdapter.SUPPORTED_AUTH_METHODS
    assert "other" in NormalizingAdapter.SUPPORTED_AUTH_METHODS
    # duplicates removed -> length should be 2
    assert len(NormalizingAdapter.SUPPORTED_AUTH_METHODS) == 2


def test_declared_supports_and_validate_allowed_methods_behavior():
    class A(ad_mod.AdapterInterface):
        ADAPTER_NAME = "a"
        SUPPORTED_AUTH_METHODS = ("m1", "m2")

        @classmethod
        def from_dict(cls, config: Dict[str, Any], client_id: str):
            return cls(_make_config(cls.ADAPTER_NAME))

        def authenticate(self, proof_context, allowed_methods=None):
            raise NotImplementedError()

    # declared_auth_methods
    declared = A.declared_auth_methods()
    assert declared == {"m1", "m2"}

    # supports_auth_method: case-insensitive check
    assert A.supports_auth_method("M1") is True
    assert A.supports_auth_method("unknown") is False

    # validate_allowed_methods returns known and unknown sets
    known, unknown = A.validate_allowed_methods(["m1", "x"], raise_on_unknown=False)
    assert known == {"m1"}
    assert unknown == {"x"}

    # raise_on_unknown True should raise ValueError
    with pytest.raises(ValueError):
        A.validate_allowed_methods(["m1", "x"], raise_on_unknown=True)

    # Non-string in allowed_methods should raise TypeError
    with pytest.raises(TypeError):
        A.validate_allowed_methods([object()], raise_on_unknown=False)


def test_register_adapter_and_duplicate_registration(monkeypatch):
    # Ensure registry is in known clean state for the test
    registry = ad_mod._adapter_registry
    backup = dict(registry)
    try:
        registry.clear()

        class R(ad_mod.AdapterInterface):
            ADAPTER_NAME = "regtest"
            SUPPORTED_AUTH_METHODS = ("one",)

            @classmethod
            def from_dict(cls, config: Dict[str, Any], client_id: str):
                return cls(_make_config(cls.ADAPTER_NAME))

            def authenticate(self, proof_context, allowed_methods=None):
                raise NotImplementedError()

        # register via helper (simulate decorator usage)
        ad_mod.register_adapter(R)
        assert ad_mod.get_adapter("regtest") is R
        assert "regtest" in ad_mod.list_adapters()

        # duplicate registration should raise RuntimeError
        class R2(ad_mod.AdapterInterface):
            ADAPTER_NAME = "regtest"
            SUPPORTED_AUTH_METHODS = ("one",)

            @classmethod
            def from_dict(cls, config: Dict[str, Any], client_id: str):
                return cls(_make_config(cls.ADAPTER_NAME))

            def authenticate(self, proof_context, allowed_methods=None):
                raise NotImplementedError()

        with pytest.raises(RuntimeError, match="already registered"):
            ad_mod.register_adapter(R2)
    finally:
        registry.clear()
        registry.update(backup)


def test_init_requires_adapterconfig_and_matching_adapter_name():
    class T(ad_mod.AdapterInterface):
        ADAPTER_NAME = "tname"
        SUPPORTED_AUTH_METHODS = ("m",)

        @classmethod
        def from_dict(cls, config: Dict[str, Any], client_id: str):
            return cls(_make_config(cls.ADAPTER_NAME))

        def authenticate(self, proof_context, allowed_methods=None):
            raise NotImplementedError()

    # Passing something that's not AdapterConfig should raise TypeError
    with pytest.raises(TypeError, match="AdapterConfig must be AdapterConfig instance"):
        T(config="not-a-config")  # type: ignore[arg-type]

    # Passing AdapterConfig with mismatched adapter_name should raise TypeError
    cfg = _make_config("other-name")
    with pytest.raises(TypeError, match="does not match adapter class ADAPTER_NAME"):
        T(cfg)


def test_supports_auth_method_typecheck():
    class U(ad_mod.AdapterInterface):
        ADAPTER_NAME = "u"
        SUPPORTED_AUTH_METHODS = ("x",)

        @classmethod
        def from_dict(cls, config: Dict[str, Any], client_id: str):
            return cls(_make_config(cls.ADAPTER_NAME))

        def authenticate(self, proof_context, allowed_methods=None):
            raise NotImplementedError()

    # Non-string argument should raise TypeError
    with pytest.raises(TypeError):
        U.supports_auth_method(123)  # type: ignore[arg-type]


def test_init_subclass_rejects_missing_adapter_name():
    # Creating a subclass without ADAPTER_NAME should raise at class creation time
    with pytest.raises(TypeError):
        type("NoNameAdapter", (ad_mod.AdapterInterface,), {"SUPPORTED_AUTH_METHODS": ("m",)})


def test_init_subclass_rejects_nonstring_adapter_name():
    with pytest.raises(TypeError):
        type("BadNameAdapter", (ad_mod.AdapterInterface,), {"ADAPTER_NAME": 123, "SUPPORTED_AUTH_METHODS": ("m",)})


def test_init_subclass_requires_supported_auth_methods():
    # missing SUPPORTED_AUTH_METHODS
    with pytest.raises(TypeError):
        type("NoMethodsAdapter", (ad_mod.AdapterInterface,), {"ADAPTER_NAME": "x"})

    # must be tuple
    with pytest.raises(TypeError):
        type("ListMethodsAdapter", (ad_mod.AdapterInterface,), {"ADAPTER_NAME": "x", "SUPPORTED_AUTH_METHODS": ["a", "b"]})

    # entries must be non-empty strings
    with pytest.raises(TypeError):
        type("BadEntriesAdapter", (ad_mod.AdapterInterface,), {"ADAPTER_NAME": "x", "SUPPORTED_AUTH_METHODS": (None,)})


def test_supported_methods_are_normalized_and_deduped():
    Cname = "NormalizeAdapter"
    cls = type(Cname, (ad_mod.AdapterInterface,), {"ADAPTER_NAME": Cname, "SUPPORTED_AUTH_METHODS": ("X", "x ", " Y ")})
    # class creation should succeed; methods normalized to lowercase, whitespace trimmed, duplicates removed preserving order
    assert hasattr(cls, "SUPPORTED_AUTH_METHODS")
    assert tuple(cls.SUPPORTED_AUTH_METHODS) == ("x", "y")
    assert cls.declared_auth_methods() == {"x", "y"}


def test_supports_auth_method_type_check_and_behavior():
    Cname = "SupportsAdapter"
    cls = type(Cname, (ad_mod.AdapterInterface,), {"ADAPTER_NAME": Cname, "SUPPORTED_AUTH_METHODS": ("m1",)})
    # non-string input should raise TypeError
    with pytest.raises(TypeError):
        cls.supports_auth_method(123)  # type: ignore[arg-type]
    assert cls.supports_auth_method("m1") is True
    assert cls.supports_auth_method("M1") is True


def test_validate_allowed_methods_strict_type_checks_and_unknown_behavior():
    Cname = "ValidateAdapter"
    cls = type(Cname, (ad_mod.AdapterInterface,), {"ADAPTER_NAME": Cname, "SUPPORTED_AUTH_METHODS": ("a", "b")})

    # non-iterable allowed_methods should raise
    with pytest.raises(TypeError):
        cls.validate_allowed_methods(123)  # type: ignore[arg-type]

    # non-string entry in iterable should raise
    with pytest.raises(TypeError):
        cls.validate_allowed_methods(["a", 1])  # type: ignore[list-item]

    # known/unknown separation
    known, unknown = cls.validate_allowed_methods(["A", "z"])
    assert known == {"a"}
    assert unknown == {"z"}

    # raise_on_unknown triggers ValueError
    with pytest.raises(ValueError):
        cls.validate_allowed_methods(["x"], raise_on_unknown=True)


def test_proofcontext_get_getlist_and_header_behaviour():
    # form contains various shapes: scalar, list, missing
    form = {"one": "v1", "many": ["m1", "m2"]}
    headers = {"X-My-Header": "h1", "other": "h2"}
    ctx = ad_mod.ProofContext(form=form, headers=headers)

    # get returns scalar value
    assert ctx.get("one") == "v1"
    # get returns first element from list
    assert ctx.get("many") == "m1"
    # get returns default when missing
    assert ctx.get("missing", default="d") == "d"

    # getlist returns [] for missing
    assert ctx.getlist("missing") == []
    # getlist wraps scalar into list
    assert ctx.getlist("one") == ["v1"]
    # getlist returns list unchanged
    assert ctx.getlist("many") == ["m1", "m2"]

    # header lookup is case-insensitive
    assert ctx.header("x-my-header") == "h1"
    assert ctx.header("OTHER") == "h2"
    # missing header returns default
    assert ctx.header("nope", default="d") == "d"


def test_subject_validation_and_to_sub():
    # valid subject works
    s = ad_mod.Subject(provider="prov", subject_id="sid")
    assert s.provider == "prov"
    assert s.subject_id == "sid"
    assert s.to_sub() == f"{ad_mod.DEFAULT_CLIENT_AUTH_URN}:prov:sid"

    # empty provider/subject_id raise via validators
    with pytest.raises(Exception):
        ad_mod.Subject(provider="", subject_id="sid")
    with pytest.raises(Exception):
        ad_mod.Subject(provider="prov", subject_id="")

    # whitespace in provider/subject_id -> ValidationError
    with pytest.raises(Exception):
        ad_mod.Subject(provider="has space", subject_id="sid")
    with pytest.raises(Exception):
        ad_mod.Subject(provider="prov", subject_id="has space")

    # provider length > 32 should raise
    long_provider = "p" * 33
    with pytest.raises(Exception):
        ad_mod.Subject(provider=long_provider, subject_id="ok")


def test_validate_allowed_methods_none_returns_empty_sets():
    # allowed_methods None should yield empty known/unknown sets
    Cname = "NoneAllowedMethodsAdapter"
    cls = type(Cname, (ad_mod.AdapterInterface,), {"ADAPTER_NAME": Cname, "SUPPORTED_AUTH_METHODS": ("a",)})
    known, unknown = cls.validate_allowed_methods(None)
    assert known == set()
    assert unknown == set()


def test_register_adapter_type_error_on_bad_class_and_cleanup_of_registry():
    # Trying to register a class that lacks ADAPTER_NAME should raise RuntimeError
    Bad = type("BadForRegister", (object,), {"SUPPORT": ()})
    with pytest.raises(RuntimeError):
        ad_mod.register_adapter(Bad)  # type: ignore[arg-type]

    # registry cleanup test: ensure list_adapters returns a copy not the internal dict
    backup = dict(ad_mod._adapter_registry)
    try:
        # register a temporary good adapter
        GoodName = "tmp-reg"
        Good = type("GoodForRegister", (ad_mod.AdapterInterface,), {"ADAPTER_NAME": GoodName, "SUPPORTED_AUTH_METHODS": ("m",)})
        ad_mod.register_adapter(Good)
        all_map = ad_mod.list_adapters()
        assert GoodName in all_map and all_map[GoodName] is Good
        # mutate returned map should not affect module registry
        all_map.pop(GoodName, None)
        assert ad_mod.get_adapter(GoodName) is Good
    finally:
        ad_mod._adapter_registry.clear()
        ad_mod._adapter_registry.update(backup)
