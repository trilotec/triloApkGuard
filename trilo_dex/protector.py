"""Main protection orchestrator."""

import os
import shutil
import tempfile

from .encryptor import (
    DexMeta,
    derive_aes_key,
    encrypt_dex_file,
    write_dexmeta,
)
from .key_management import CommunityKeyManager, KeyManager
from .manifest import modify_axml
from .native_build import compile_native_lib
from .parser import ApkError, DexNotFoundError, extract_apk, find_dex_files, verify_apk_structure
from .repacker import repackage_apk
from .signer import SigningError, sign_apk, zipalign_apk


def _log(msg: str) -> None:
    print(f"[*] {msg}")


STUB_APP_NAME = "com.trilo.stub.StubApplication"


class TriloDexError(Exception):
    pass


class SmaliError(TriloDexError):
    pass


def protect_apk(
    input_apk: str,
    output_apk: str,
    sdk_dir: str | None = None,
    skip_sign: bool = False,
    verbose: bool = False,
    progress_callback=None,
    key_manager: KeyManager | None = None,
) -> dict:
    """Protect an APK file."""
    tmp_dir = None
    try:
        key_manager = key_manager or CommunityKeyManager()
        tmp_dir = tempfile.mkdtemp(prefix="trilodex_")
        if verbose:
            _log(f"Working directory: {tmp_dir}")

        _log("Extracting APK...")
        extract_dir = os.path.join(tmp_dir, "extracted")
        os.makedirs(extract_dir)
        extract_apk(input_apk, extract_dir)
        verify_apk_structure(extract_dir)
        if progress_callback:
            progress_callback("extract", 10)

        dex_files = find_dex_files(extract_dir)
        dex_count = len(dex_files)
        _log(f"Found {dex_count} DEX file(s)")
        for _, name in dex_files:
            _log(f"  - {name}")
        if progress_callback:
            progress_callback("find_dex", 15)

        _log("Generating key material...")
        key_material = key_manager.generate(input_apk)
        aes_key = derive_aes_key(key_material.seed)
        _log(f"  Key scheme: {key_material.scheme_id}")
        _log(f"  Seed: {key_material.seed.hex()}")
        _log(f"  Derive-A: {key_material.derive_a.hex()}")
        _log(f"  Derive-C: {key_material.derive_c.hex()}")
        if progress_callback:
            progress_callback("generate_key", 25)

        _log("Encrypting DEX files...")
        assets_dir = os.path.join(extract_dir, "assets")
        os.makedirs(assets_dir, exist_ok=True)

        dex_meta = DexMeta()
        for i, (dex_path, dex_name) in enumerate(dex_files):
            enc_name = "encrypted_classes.dat" if i == 0 else f"encrypted_classes{i + 1}.dat"
            enc_path = os.path.join(assets_dir, enc_name)
            enc_info = encrypt_dex_file(dex_path, aes_key, enc_path)
            dex_meta.files.append(enc_info)
            _log(f"  Encrypted {dex_name} -> {enc_name}")
            os.unlink(dex_path)

        write_dexmeta(dex_meta, os.path.join(assets_dir, ".dexmeta"))
        key_manager.write_runtime_assets(assets_dir, key_material)
        if progress_callback:
            progress_callback("encrypt", 50)

        _log("Building native key storage...")
        lib_dir = os.path.join(extract_dir, "lib", "arm64-v8a")
        os.makedirs(lib_dir, exist_ok=True)
        so_path = os.path.join(lib_dir, "libtrilocfg.so")

        ndk_clang = None
        if sdk_dir:
            from .tools import _find_ndk_clang

            ndk_clang = _find_ndk_clang(sdk_dir)

        compile_native_lib(key_material.derive_b, so_path, ndk_clang=ndk_clang)
        _log(f"  Built {so_path}")
        if progress_callback:
            progress_callback("native", 65)

        _log("Compiling stub...")
        stub_dex = _compile_stub_smali(extract_dir, sdk_dir, key_material.derive_a)
        if progress_callback:
            progress_callback("stub", 75)

        _log("Injecting stub...")
        classes_dex = os.path.join(extract_dir, "classes.dex")
        shutil.copy2(stub_dex, classes_dex)
        os.unlink(stub_dex)
        if progress_callback:
            progress_callback("inject", 80)

        _log("Modifying manifest...")
        _modify_manifest(extract_dir)
        if progress_callback:
            progress_callback("manifest", 85)

        _log("Repackaging APK...")
        repackage_apk(extract_dir, output_apk)
        if progress_callback:
            progress_callback("repack", 90)

        if sdk_dir and not skip_sign:
            _log("Running zipalign...")
            aligned_path = output_apk.replace(".apk", "_aligned.apk")
            zipalign_apk(output_apk, aligned_path, sdk_dir)
            if aligned_path != output_apk:
                os.replace(aligned_path, output_apk)

        if not skip_sign:
            _log("Signing APK...")
            sign_apk(output_apk, output_apk, sdk_dir)
        if progress_callback:
            progress_callback("sign", 100)

        _log(f"Protected APK: {output_apk}")
        return {
            "output": output_apk,
            "seed_hex": key_material.seed.hex(),
            "derive_b_hex": key_material.derive_b.hex(),
            "key_scheme": key_material.scheme_id,
            "dex_count": dex_count,
        }
    finally:
        if tmp_dir and os.path.isdir(tmp_dir):
            shutil.rmtree(tmp_dir)


def _compile_stub_smali(extract_dir: str, sdk_dir: str | None, derive_a: bytes) -> str:
    """Compile smali stub files to a DEX file."""
    import subprocess as sp

    from .tools import _find_smali_jar

    smali_jar = _find_smali_jar()
    if not smali_jar:
        raise SmaliError(
            "smali.jar not found. Set SMALI_JAR env var or download smali.jar "
            "from https://github.com/baksmali/smali/releases"
        )

    stub_dir = os.path.join(os.path.dirname(__file__), "..", "stub")
    if not os.path.isdir(stub_dir):
        stub_dir = os.path.join(os.getcwd(), "stub")
    if not os.path.isdir(stub_dir):
        raise SmaliError(f"Stub directory not found: {stub_dir}")

    tmp_stub = tempfile.mkdtemp(prefix="stub_")
    for fname in os.listdir(stub_dir):
        src = os.path.join(stub_dir, fname)
        dst = os.path.join(tmp_stub, fname)
        if os.path.isfile(src):
            shutil.copy2(src, dst)

    _patch_derive_a_in_smali(tmp_stub, derive_a)

    stub_dex = os.path.join(extract_dir, "stub.dex")
    cmd = ["java", "-jar", smali_jar, "assemble", "-o", stub_dex, tmp_stub]
    result = sp.run(cmd, capture_output=True, text=True)
    shutil.rmtree(tmp_stub)
    if result.returncode != 0 or result.stderr.strip():
        raise SmaliError(f"smali compilation failed: {result.stderr}")
    if not os.path.isfile(stub_dex):
        raise SmaliError("smali compilation produced no output")
    return stub_dex


def _patch_derive_a_in_smali(smali_dir: str, derive_a: bytes) -> None:
    """Patch StubApplication.smali to use a hardcoded Derive-A value."""
    import re

    smali_path = os.path.join(smali_dir, "StubApplication.smali")
    if not os.path.isfile(smali_path):
        return

    with open(smali_path, "r", encoding="utf-8") as f:
        content = f.read()

    bytes_str = "\n".join(f"        0x{b:02x}t" for b in derive_a)
    new_method = f""".method private static deriveA(Landroid/content/Context;)[B
    .registers 3

    const/16 v0, 0x10
    new-array v0, v0, [B

    fill-array-data v0, :array_data

    return-object v0

    :array_data
    .array-data 1
{bytes_str}
    .end array-data
.end method"""

    pattern = r"\.method private static deriveA\(Landroid/content/Context;\)\[B.*?\.end method"
    patched = re.sub(pattern, new_method, content, count=1, flags=re.DOTALL)
    if patched == content:
        raise SmaliError("Could not patch deriveA method in StubApplication.smali")

    with open(smali_path, "w", encoding="utf-8") as f:
        f.write(patched)

def _modify_manifest(extract_dir: str) -> None:
    """Modify AndroidManifest.xml to use StubApplication."""
    manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")
    modify_axml(manifest_path, STUB_APP_NAME)
