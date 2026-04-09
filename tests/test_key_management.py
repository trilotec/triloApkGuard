"""Tests for public key-management boundaries."""

from trilo_dex.key_management import CommunityKeyManager, reconstruct_seed


class _FakeApk:
    def __init__(self, _path: str):
        self._path = _path

    def get_package(self) -> str:
        return "com.example.demo"

    def get_min_sdk_version(self) -> str:
        return "23"

    def get_target_sdk_version(self) -> str:
        return "34"


def test_community_key_manager_generates_runtime_material(monkeypatch):
    monkeypatch.setattr("trilo_dex.key_management.APK", _FakeApk)
    monkeypatch.setattr(
        "trilo_dex.key_management.generate_derive_b",
        lambda: bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    monkeypatch.setattr(
        "trilo_dex.key_management._generate_seed",
        lambda: bytes.fromhex("ffeeddccbbaa99887766554433221100"),
    )

    manager = CommunityKeyManager()
    material = manager.generate("dummy.apk")

    assert material.scheme_id == "community-v1"
    assert len(material.seed) == 16
    assert len(material.derive_a) == 16
    assert len(material.derive_b) == 16
    assert len(material.derive_c) == 16


def test_reconstruct_seed_matches_generated_material(monkeypatch):
    monkeypatch.setattr("trilo_dex.key_management.APK", _FakeApk)
    monkeypatch.setattr(
        "trilo_dex.key_management.generate_derive_b",
        lambda: bytes.fromhex("00112233445566778899aabbccddeeff"),
    )
    monkeypatch.setattr(
        "trilo_dex.key_management._generate_seed",
        lambda: bytes.fromhex("ffeeddccbbaa99887766554433221100"),
    )

    manager = CommunityKeyManager()
    material = manager.generate("dummy.apk")

    assert reconstruct_seed(material) == material.seed
