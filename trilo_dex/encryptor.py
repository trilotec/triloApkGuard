"""triloSec encryption module."""

import json
import os
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass
class EncryptedFile:
    encrypted_name: str
    original_name: str
    nonce_hex: str
    gcm_tag_hex: str
    original_size: int


@dataclass
class DexMeta:
    version: int = 1
    algorithm: str = "triloSec-v1"
    files: list[EncryptedFile] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "algorithm": self.algorithm,
            "files": [
                {
                    "encrypted_name": f.encrypted_name,
                    "original_name": f.original_name,
                    "nonce_hex": f.nonce_hex,
                    "gcm_tag_hex": f.gcm_tag_hex,
                    "original_size": f.original_size,
                }
                for f in self.files
            ],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def generate_seed() -> bytes:
    """Generate a random 16-byte seed for key derivation."""
    return secrets.token_bytes(16)


def derive_aes_key(seed: bytes) -> bytes:
    """Use the 16-byte seed directly as the AES-GCM key."""
    if len(seed) != 16:
        raise ValueError(f"seed must be 16 bytes, got {len(seed)}")
    return seed


def encrypt_dex_file(dex_path: str, aes_key: bytes, output_path: str) -> EncryptedFile:
    """Encrypt a DEX file using AES-GCM.

    Output format: [12B nonce][ciphertext + 16B GCM tag]
    """
    with open(dex_path, "rb") as f:
        plaintext = f.read()

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(aes_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    with open(output_path, "wb") as f:
        f.write(nonce)
        f.write(ciphertext_with_tag)

    gcm_tag = ciphertext_with_tag[-16:]

    return EncryptedFile(
        encrypted_name=os.path.basename(output_path),
        original_name=os.path.basename(dex_path),
        nonce_hex=nonce.hex(),
        gcm_tag_hex=gcm_tag.hex(),
        original_size=len(plaintext),
    )


def write_dexmeta(meta: DexMeta, output_path: str) -> None:
    """Write .dexmeta JSON file."""
    with open(output_path, "w") as f:
        f.write(meta.to_json())
