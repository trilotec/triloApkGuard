"""Tests for triloSec encryption module."""

import os
import tempfile

from trilo_dex.encryptor import (
    derive_aes_key,
    encrypt_dex_file,
    generate_seed,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_generate_seed():
    seed = generate_seed()
    assert len(seed) == 16
    # Ensure randomness
    seed2 = generate_seed()
    assert seed != seed2


def test_derive_aes_key():
    seed = generate_seed()
    key = derive_aes_key(seed)
    assert len(key) == 16  # 128 bits

    # Deterministic: same seed → same key
    key2 = derive_aes_key(seed)
    assert key == key2

    # Different seed → different key
    key3 = derive_aes_key(generate_seed())
    assert key != key3


def test_encrypt_decrypt_roundtrip():
    """Test that encrypted data can be decrypted back to original."""
    seed = generate_seed()
    aes_key = derive_aes_key(seed)

    # Create a fake DEX file
    with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as f:
        f.write(b"dex\n035\x00" + b"\x00" * 100)
        dex_path = f.name

    enc_path = dex_path + ".enc"

    try:
        enc_info = encrypt_dex_file(dex_path, aes_key, enc_path)

        # Verify output file exists and has correct format
        assert os.path.isfile(enc_path)
        assert os.path.getsize(enc_path) > 28  # 12B nonce + 16B tag + data

        # Read encrypted file and decrypt manually
        with open(enc_path, "rb") as f:
            data = f.read()

        nonce = data[:12]
        ciphertext_with_tag = data[12:]

        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        # Verify roundtrip
        with open(dex_path, "rb") as f:
            original = f.read()

        assert plaintext == original
        assert enc_info.original_size == len(original)

    finally:
        os.unlink(dex_path)
        if os.path.exists(enc_path):
            os.unlink(enc_path)


def test_encrypt_different_keys():
    """Test that different keys produce different ciphertext."""
    key1 = derive_aes_key(generate_seed())
    key2 = derive_aes_key(generate_seed())

    with tempfile.NamedTemporaryFile(suffix=".dex", delete=False) as f:
        f.write(b"test dex data")
        dex_path = f.name

    enc1 = dex_path + ".enc1"
    enc2 = dex_path + ".enc2"

    try:
        encrypt_dex_file(dex_path, key1, enc1)
        encrypt_dex_file(dex_path, key2, enc2)

        with open(enc1, "rb") as f:
            data1 = f.read()
        with open(enc2, "rb") as f:
            data2 = f.read()

        # Different keys → different nonces and ciphertext
        assert data1 != data2

    finally:
        os.unlink(dex_path)
        for p in [enc1, enc2]:
            if os.path.exists(p):
                os.unlink(p)
