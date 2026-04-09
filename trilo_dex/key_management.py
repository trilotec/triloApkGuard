"""Key-management abstractions for public and private editions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from androguard.core.apk import APK

from .native_build import generate_derive_b


@dataclass(frozen=True)
class RuntimeKeyMaterial:
    """Material required by the runtime loader."""

    scheme_id: str
    seed: bytes
    derive_a: bytes
    derive_b: bytes
    derive_c: bytes


class KeyManager(ABC):
    """Public extension point for runtime key strategies."""

    @property
    @abstractmethod
    def scheme_id(self) -> str:
        """Stable identifier for the key-management scheme."""

    @abstractmethod
    def generate(self, input_apk: str) -> RuntimeKeyMaterial:
        """Generate runtime key material for a protected APK."""

    @abstractmethod
    def write_runtime_assets(self, assets_dir: str | Path, material: RuntimeKeyMaterial) -> None:
        """Write any assets consumed by the runtime loader."""


class CommunityKeyManager(KeyManager):
    """Public, inspectable key strategy used by the community edition."""

    scheme_id = "community-v1"
    runtime_asset_name = "trilodata.bin"

    def generate(self, input_apk: str) -> RuntimeKeyMaterial:
        seed = _generate_seed()
        derive_a = self._compute_derive_a(input_apk)
        derive_b = generate_derive_b()
        derive_c = bytes(seed[i] ^ derive_a[i] ^ derive_b[i] for i in range(16))
        return RuntimeKeyMaterial(
            scheme_id=self.scheme_id,
            seed=seed,
            derive_a=derive_a,
            derive_b=derive_b,
            derive_c=derive_c,
        )

    def write_runtime_assets(self, assets_dir: str | Path, material: RuntimeKeyMaterial) -> None:
        assets_path = Path(assets_dir)
        assets_path.mkdir(parents=True, exist_ok=True)
        (assets_path / self.runtime_asset_name).write_bytes(material.derive_c)

    @staticmethod
    def _compute_derive_a(apk_path: str) -> bytes:
        import hashlib

        apk = APK(apk_path)
        package_name = apk.get_package()
        min_sdk = apk.get_min_sdk_version()
        target_sdk = apk.get_target_sdk_version()
        digest = hashlib.sha256(f"{package_name}|{min_sdk}|{target_sdk}".encode("utf-8")).digest()
        return digest[:16]


def reconstruct_seed(material: RuntimeKeyMaterial) -> bytes:
    """Reconstruct the runtime seed from the public contract."""
    if not all(len(part) == 16 for part in (material.seed, material.derive_a, material.derive_b, material.derive_c)):
        raise ValueError("runtime key material must use 16-byte parts")
    return bytes(
        material.derive_a[i] ^ material.derive_b[i] ^ material.derive_c[i]
        for i in range(16)
    )


def _generate_seed() -> bytes:
    import secrets

    return secrets.token_bytes(16)
