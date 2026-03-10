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
import tempfile
import os
from typing import Dict, Any
from pathlib import Path

from credenza.api.auth.client import client_registry as cr
from credenza.api.auth.client.adapters import adapter as adapter_mod
from credenza.api.auth.client.adapters.adapter import AdapterConfig
from credenza.api.auth.client.client_registry import (
    _validate_adapter_instance,
    _validate_adapter_config,
    _normalize_list_field,
    fingerprint_client_record,
    load_client_registry,
    ClientRecord,
)

class DummyAdapterConfig(adapter_mod.AdapterConfig):
    # keep fields compatible; AdapterConfig is frozen dataclass in real code but for tests we just construct
    pass


@adapter_mod.register_adapter
class DummyAdapter(adapter_mod.AdapterInterface[adapter_mod.AdapterConfig]):
    ADAPTER_NAME = "dummy"
    SUPPORTED_AUTH_METHODS = ("dummy_method",)

    def __init__(self, config: adapter_mod.AdapterConfig):
        # AdapterInterface enforces adapter_name match in __init__, so pass a compatible config in tests
        super().__init__(config)

    @classmethod
    def from_dict(cls, config: Dict[str, Any], client_id: str):
        # Build an AdapterConfig compatible object expected by AdapterInterface
        cfg = adapter_mod.AdapterConfig(
            client_id=str(client_id),
            adapter_name=cls.ADAPTER_NAME,
            config_dict=config,
        )
        return cls(cfg)

    def authenticate(self, proof_context, allowed_methods=None):
        raise NotImplementedError()


def write_registry(tmp_path: Path, payload: Dict[str, Any]) -> Path:
    p = tmp_path / "clients.json"
    p.write_text(json.dumps(payload, ensure_ascii=False))
    return p


def test_load_registry_requires_clients_key(tmp_path):
    # missing top-level 'clients' should raise
    p = write_registry(tmp_path, {"version": "1"})
    with pytest.raises(ValueError, match="client registry missing top-level 'clients'"):
        cr.load_client_registry(str(p))


def test_missing_adapter_name_raises(tmp_path):
    # adapter block present but missing adapter_name/name/method should raise
    payload = {
        "version": "1",
        "clients": {
            "c1": {
                "adapter": {"some": "value"}
            }
        }
    }
    p = write_registry(tmp_path, payload)
    with pytest.raises(ValueError, match="adapter.adapter_name .* missing"):
        cr.load_client_registry(str(p))


def test_unknown_adapter_name_raises(tmp_path):
    # adapter_name that isn't registered should raise
    payload = {
        "version": "1",
        "clients": {
            "c2": {
                "adapter": {"adapter_name": "no_such_adapter"}
            }
        }
    }
    p = write_registry(tmp_path, payload)
    with pytest.raises(ValueError, match="No adapter registered for adapter_name"):
        cr.load_client_registry(str(p))

def test_validate_adapter_instance_raises_on_wrong_type():
    class FakeAdapter(adapter_mod.AdapterInterface[adapter_mod.AdapterConfig]):
        ADAPTER_NAME = "fake"
        SUPPORTED_AUTH_METHODS = ("fake",)

        @classmethod
        def from_dict(cls, config, client_id):
            raise NotImplementedError()

        def authenticate(self, proof_context, allowed_methods=None):
            raise NotImplementedError()

    # instance is NOT an instance of FakeAdapter
    bad_instance = object()

    with pytest.raises(ValueError) as exc:
        cr._validate_adapter_instance(bad_instance, FakeAdapter, "cid123")

    assert "cid123" in str(exc.value)
    assert "did not return an instance" in str(exc.value)


def test_validate_adapter_instance_raises_on_subclass_mismatch():
    class A(adapter_mod.AdapterInterface[adapter_mod.AdapterConfig]):
        ADAPTER_NAME = "a"
        SUPPORTED_AUTH_METHODS = ("a",)

        @classmethod
        def from_dict(cls, config, client_id):
            raise NotImplementedError()

        def authenticate(self, proof_context, allowed_methods=None):
            raise NotImplementedError()

    class B(adapter_mod.AdapterInterface[adapter_mod.AdapterConfig]):
        ADAPTER_NAME = "b"
        SUPPORTED_AUTH_METHODS = ("b",)

        @classmethod
        def from_dict(cls, config, client_id):
            raise NotImplementedError()

        def authenticate(self, proof_context, allowed_methods=None):
            raise NotImplementedError()

    # Create instance of B but validate against A
    cfg = adapter_mod.AdapterConfig(
        client_id="x",
        adapter_name="b",
        config_dict={}
    )
    b_instance = B(cfg)

    with pytest.raises(ValueError):
        cr._validate_adapter_instance(b_instance, A, "cid456")


def test_validate_adapter_config_raises_on_none():
    with pytest.raises(ValueError) as exc:
        cr._validate_adapter_config(None, "cid789")

    assert "cid789" in str(exc.value)
    assert "invalid `.config` attribute" in str(exc.value)


def test_validate_adapter_config_raises_on_wrong_type():
    class NotAdapterConfig:
        pass

    with pytest.raises(ValueError):
        cr._validate_adapter_config(NotAdapterConfig(), "cid000")


def test_load_registry_instantiates_adapter_and_fields(tmp_path):
    # valid client with dummy adapter should instantiate adapter and populate ClientRecord
    payload = {
        "version": "1",
        "clients": {
            "my-client": {
                "desc": "Example client",
                "enabled": True,
                "public": True,
                "adapter": {
                    "adapter_name": "dummy",
                    "extra": "cfg"
                },
                "allowed_scopes": ["read", "Write"],  # mixed case to test normalization in fingerprint
                "allowed_claims": ["email", "name"],
                "additional_claims": {"x": "y"},
            }
        }
    }
    p = write_registry(tmp_path, payload)
    registry = cr.load_client_registry(str(p))
    assert registry.version == "1"
    assert "my-client" in registry.clients
    crec = registry.clients["my-client"]
    assert crec.client_id == "my-client"
    assert crec.desc == "Example client"
    assert crec.public is True
    # adapter instance should be created and be instance of DummyAdapter
    assert crec.adapter_instance is not None
    assert isinstance(crec.adapter_instance, DummyAdapter)
    # adapter_config present and has adapter_name
    assert crec.adapter_config is not None
    assert crec.adapter_config.adapter_name == "dummy"
    # fingerprint computed
    assert crec.fingerprint and isinstance(crec.fingerprint, str)


def test_fingerprint_normalizes_list_fields(tmp_path):
    # Create two registry files where allowed_scopes differ only by order/case; fingerprints for same client_id should be identical
    base_payload = {
        "version": "1",
        "clients": {
            "cliA": {
                "adapter": {"adapter_name": "dummy"},
                "allowed_scopes": ["read", "write", "admin"]
            }
        }
    }
    alt_payload = {
        "version": "1",
        "clients": {
            "cliA": {
                "adapter": {"adapter_name": "dummy"},
                "allowed_scopes": ["ADMIN", "Write", "Read"]  # different order and case
            }
        }
    }
    p1 = write_registry(tmp_path, base_payload)
    p2 = write_registry(tmp_path, alt_payload)  # overwrites same file name; that's fine, we load separately
    r1 = cr.load_client_registry(str(p1))
    # write second to a different filename to avoid overwriting when reusing helper
    p2b = tmp_path / "clients2.json"
    p2b.write_text(json.dumps(alt_payload, ensure_ascii=False))
    r2 = cr.load_client_registry(str(p2b))
    fp1 = r1.clients["cliA"].fingerprint
    fp2 = r2.clients["cliA"].fingerprint
    assert fp1 == fp2, "fingerprint should be stable despite case/order differences in list fields"


def test_validate_adapter_instance_negative():
    class Foo: ...
    class Bar: ...
    with pytest.raises(ValueError, match="did not return an instance"):
        _validate_adapter_instance(Foo(), Bar, "cid-1")


def test_validate_adapter_config_negative():
    # adapter_config must be an AdapterConfig instance
    with pytest.raises(ValueError, match="invalid `.config` attribute"):
        _validate_adapter_config({"not": "an adapterconfig"}, "cid-2")


def test_normalize_list_field_with_iterable_and_case_and_sorting():
    vals = ["B", "a", "A", "b", None, "  c  "]
    norm = _normalize_list_field(vals)
    # lowercased, stripped, deduped, sorted
    assert norm == ["a", "b", "c"]


def test_normalize_list_field_iteration_error_propagates():
    # An object whose __iter__ raises should propagate (we want fail-fast)
    class BadIter:
        def __iter__(self):
            raise RuntimeError("iter failure")
    with pytest.raises(RuntimeError):
        _normalize_list_field(BadIter())


def _write_temp_registry(data) -> str:
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8")
    json.dump(data, tf)
    tf.flush()
    tf.close()
    return tf.name


def test_load_client_registry_missing_clients_key(tmp_path):
    path = _write_temp_registry({"version": "1"})
    try:
        with pytest.raises(ValueError, match="missing top-level 'clients'"):
            load_client_registry(path)
    finally:
        os.unlink(path)


def test_load_client_registry_clients_not_object(tmp_path):
    path = _write_temp_registry({"clients": []})
    try:
        with pytest.raises(ValueError, match="must be an object"):
            load_client_registry(path)
    finally:
        os.unlink(path)


def test_load_client_registry_client_entry_not_object(tmp_path):
    path = _write_temp_registry({"clients": {"c1": "notobj"}})
    try:
        with pytest.raises(ValueError, match="client entry for c1 must be an object"):
            load_client_registry(path)
    finally:
        os.unlink(path)


def test_load_client_registry_adapter_block_missing_adapter_name(monkeypatch, tmp_path):
    # Build minimal clients JSON with adapter block but no adapter_name/method
    data = {"clients": {"c1": {"adapter": {}}}}
    path = _write_temp_registry(data)
    try:
        with pytest.raises(ValueError, match="adapter.adapter_name"):
            load_client_registry(path)
    finally:
        os.unlink(path)


def test_load_client_registry_adapter_unknown(monkeypatch, tmp_path):
    # adapter_name provided but get_adapter returns None
    data = {"clients": {"c1": {"adapter": {"adapter_name": "missing"}}}}
    path = _write_temp_registry(data)
    try:
        # monkeypatch the get_adapter in the module to simulate missing adapter
        monkeypatch.setattr(cr, "get_adapter", lambda name: None)
        with pytest.raises(ValueError, match="No adapter registered for adapter_name=missing"):
            load_client_registry(path)
    finally:
        os.unlink(path)


def test_load_client_registry_adapter_from_dict_raises(monkeypatch, tmp_path):
    # Simulate adapter class whose from_dict raises
    class DummyAdapterClass:
        ADAPTER_NAME = "dummy"
        @classmethod
        def from_dict(cls, cfg, client_id):
            raise RuntimeError("factory blowup")

    data = {"clients": {"c1": {"adapter": {"adapter_name": "dummy"}}}}
    path = _write_temp_registry(data)
    try:
        monkeypatch.setattr(cr, "get_adapter", lambda name: DummyAdapterClass)
        with pytest.raises(RuntimeError, match="from_dict failed"):
            load_client_registry(path)
    finally:
        os.unlink(path)


def test_load_client_registry_adapter_from_dict_returns_wrong_type(monkeypatch, tmp_path):
    # Simulate adapter class whose from_dict returns an object that is not an instance of the adapter class
    class DummyAdapterClass:
        ADAPTER_NAME = "dummy2"
        @classmethod
        def from_dict(cls, cfg, client_id):
            return object()  # wrong type

    data = {"clients": {"c1": {"adapter": {"adapter_name": "dummy2"}}}}
    path = _write_temp_registry(data)
    try:
        monkeypatch.setattr(cr, "get_adapter", lambda name: DummyAdapterClass)
        # The loader will call _validate_adapter_instance which should raise ValueError
        with pytest.raises(ValueError, match="did not return an instance"):
            load_client_registry(path)
    finally:
        os.unlink(path)


def test_load_client_registry_adapter_config_invalid(monkeypatch, tmp_path):
    # Simulate adapter class whose from_dict returns an instance of the adapter class
    # but with an invalid `.config` attribute (not an AdapterConfig instance)
    class DummyAdapterClass:
        ADAPTER_NAME = "dummy3"

        def __init__(self):
            # invalid config on purpose
            self.config = {"not": "AdapterConfig"}

        @classmethod
        def from_dict(cls, cfg, client_id):
            return cls()

    data = {"clients": {"c1": {"adapter": {"adapter_name": "dummy3"}}}}
    path = _write_temp_registry(data)
    try:
        monkeypatch.setattr(cr, "get_adapter", lambda name: DummyAdapterClass)
        with pytest.raises(ValueError, match="invalid `.config` attribute"):
            load_client_registry(path)
    finally:
        os.unlink(path)


def test_fingerprint_normalizes_list_fields_and_adapter_config():
    # Create two ClientRecord instances with same logical values but different ordering/case
    base_cfg = {"some": "val", "allowed_claims": ["X", "a"]}
    cr1 = ClientRecord(
        client_id="c1",
        desc="d",
        enabled=True,
        public=False,
        adapter_config=AdapterConfig(client_id="c1", adapter_name="a", config_dict=base_cfg),
        allowed_claims=["X", "a"],
        allowed_grant_types=["r2", "r1"],
        allowed_resources=["urn:resb", "urn:resa"],
        allowed_scopes=["S2", "s1"],
        allowed_token_exchange_targets=[]
    )
    # Build cr2 with different ordering and cases
    base_cfg2 = {"some": "val", "allowed_claims": ["a", "x", "A"]}
    cr2 = ClientRecord(
        client_id="c1",
        desc="d",
        enabled=True,
        public=False,
        adapter_config=AdapterConfig(client_id="c1", adapter_name="a", config_dict=base_cfg2),
        allowed_claims=["a", "X"],
        allowed_grant_types=["r1", "r2"],
        allowed_resources=["urn:resa", "urn:ResB"],
        allowed_scopes=["s1", "S2"],
        allowed_token_exchange_targets=[]
    )
    fp1 = fingerprint_client_record(cr1)
    fp2 = fingerprint_client_record(cr2)
    # Because normalization lowercases/dedupes/sorts list fields, the fingerprints should match
    assert isinstance(fp1, str) and len(fp1) == 64
    assert fp1 == fp2


def test_client_is_public_variants():
    cr = ClientRecord(client_id="c1", desc=None, enabled=True, public=True)
    assert cr.public is True
    cr2 = ClientRecord(client_id="c2", desc=None, enabled=True, public=False)
    assert cr2.public is False


def test_adapter_name_with_instance():
    inst = DummyAdapter.from_dict({"adapter": {"adapter_name": "dummy2"}}, "c1")
    rec = ClientRecord(client_id="c1", desc=None, enabled=True, adapter_instance=inst)
    assert rec.adapter_name == inst.ADAPTER_NAME


def test_adapter_name_none_when_missing():
    rec = ClientRecord(client_id="c1", desc=None, enabled=True, adapter_instance=None)
    assert rec.adapter_name == "none"
