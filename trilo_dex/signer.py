"""APK signing using apksigner."""

import os
import shutil
import subprocess


class SigningError(Exception):
    pass


def sign_apk(
    input_apk: str,
    output_apk: str,
    sdk_dir: str,
    keystore: str | None = None,
    keystore_pass: str | None = None,
    alias: str | None = None,
) -> None:
    """Sign APK using apksigner.

    Args:
        input_apk: Path to unsigned/unaligned APK.
        output_apk: Path for signed APK output.
        sdk_dir: Android SDK root directory.
        keystore: Path to keystore file. None = use debug keystore.
        keystore_pass: Keystore password. None = default "android".
        alias: Key alias. None = default "androiddebugkey".
    """
    apksigner = _find_apksigner(sdk_dir)
    if not apksigner:
        raise SigningError("apksigner not found. Provide --sdk-dir option.")

    # Determine keystore
    use_debug = keystore is None
    if use_debug:
        keystore = os.path.join(os.path.expanduser("~"), ".trilodex", "debug.keystore")
        keystore_pass = "android"
        alias = "androiddebugkey"

        # Generate debug keystore if it doesn't exist
        if not os.path.isfile(keystore):
            _generate_debug_keystore(keystore)

    # Build signing command
    cmd = [
        apksigner,
        "sign",
        "--ks", keystore,
        "--ks-pass", f"pass:{keystore_pass}",
        "--ks-key-alias", alias,
        "--key-pass", f"pass:{keystore_pass}",
        "--out", output_apk,
        input_apk,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SigningError(f"apksigner failed: {result.stderr}")


def zipalign_apk(
    input_apk: str,
    output_apk: str,
    sdk_dir: str,
) -> str:
    """Run zipalign on the APK.

    Args:
        input_apk: Input APK path.
        output_apk: Output aligned APK path.
        sdk_dir: Android SDK root directory.

    Returns:
        Path to aligned APK.
    """
    zipalign = _find_zipalign(sdk_dir)
    if not zipalign:
        # zipalign not available, skip
        if output_apk != input_apk:
            shutil.copy2(input_apk, output_apk)
        return output_apk

    cmd = [zipalign, "-f", "-p", "4", input_apk, output_apk]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SigningError(f"zipalign failed: {result.stderr}")

    return output_apk


def get_apk_cert_hash(apk_path: str) -> bytes:
    """Extract SHA-256 hash of the first certificate from an APK.

    Uses apksigner's --print-certs or androguard as fallback.
    Returns 32-byte hash.
    """
    import subprocess as sp

    # Try apksigner first
    apksigner = shutil.which("apksigner")
    if not apksigner:
        # Search in SDK build-tools
        for sdk_candidate in [os.environ.get("ANDROID_HOME", ""),
                               os.environ.get("ANDROID_SDK_ROOT", "")]:
            if sdk_candidate:
                apksigner = _find_sdk_tool("apksigner", sdk_candidate)
                if apksigner:
                    break

    if apksigner:
        try:
            result = sp.run(
                [apksigner, "verify", "--print-certs", apk_path],
                capture_output=True, text=True
            )
            for line in result.stdout.split("\n"):
                if "SHA-256" in line and ":" in line:
                    hex_str = line.split(":", 1)[1].strip().replace(":", "")
                    return bytes.fromhex(hex_str)
        except Exception:
            pass

    # Fallback: use androguard
    try:
        from androguard.core.apk import APK
        apk = APK(apk_path)
        certs = apk.get_certificates()
        if certs:
            import hashlib
            return hashlib.sha256(certs[0]).digest()
    except Exception:
        pass

    raise SigningError("Could not extract certificate hash from APK")


def get_cert_hash(keystore: str, keystore_pass: str, alias: str) -> bytes:
    """Get SHA-256 hash of the certificate in keystore.

    Returns 32-byte hash.
    """
    keytool = shutil.which("keytool")
    if not keytool:
        keytool = _find_keytool()
    if not keytool:
        raise SigningError("keytool not found")

    cmd = [
        keytool,
        "-exportcert",
        "-alias", alias,
        "-keystore", keystore,
        "-storepass", keystore_pass,
        "-rfc",
    ]

    result = subprocess.run(cmd, capture_output=True, check=True)
    cert_pem = result.stdout.decode("utf-8")

    # Extract DER bytes from PEM
    import base64
    lines = cert_pem.strip().split("\n")
    b64 = "".join(l for l in lines if not l.startswith("-----"))
    der_bytes = base64.b64decode(b64)

    import hashlib
    return hashlib.sha256(der_bytes).digest()


def _generate_debug_keystore(keystore_path: str) -> None:
    """Generate a debug keystore using keytool."""
    keytool = shutil.which("keytool")
    if not keytool:
        keytool = _find_keytool()
    if not keytool:
        raise SigningError("keytool not found, cannot generate debug keystore")

    os.makedirs(os.path.dirname(keystore_path), exist_ok=True)

    cmd = [
        keytool,
        "-genkeypair",
        "-v",
        "-keystore", keystore_path,
        "-storepass", "android",
        "-alias", "androiddebugkey",
        "-keypass", "android",
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-dname", "CN=Android Debug,O=Android,C=US",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SigningError(f"keytool failed: {result.stderr}")


def _find_apksigner(sdk_dir: str) -> str | None:
    """Find apksigner executable."""
    return _find_sdk_tool("apksigner", sdk_dir)


def _find_zipalign(sdk_dir: str) -> str | None:
    """Find zipalign executable."""
    return _find_sdk_tool("zipalign", sdk_dir)


def _find_keytool() -> str | None:
    """Find keytool in Java home."""
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        kt = os.path.join(java_home, "bin", "keytool")
        if os.path.isfile(kt):
            return kt
        if os.name == "nt":
            kt += ".exe"
            if os.path.isfile(kt):
                return kt
    return shutil.which("keytool")


def _find_sdk_tool(name: str, sdk_dir: str) -> str | None:
    """Find SDK tool in build-tools."""
    bt_dir = os.path.join(sdk_dir, "build-tools")
    if not os.path.isdir(bt_dir):
        return None

    for ver in sorted(os.listdir(bt_dir), reverse=True):
        candidate = os.path.join(bt_dir, ver, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
        if os.name == "nt":
            candidate_bat = candidate + ".bat"
            if os.path.isfile(candidate_bat):
                return candidate_bat

    return None
