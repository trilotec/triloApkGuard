"""APK extraction and analysis."""

import os
import re
import zipfile
from pathlib import Path


class ApkError(Exception):
    pass


class DexNotFoundError(ApkError):
    pass


def extract_apk(apk_path: str, dest_dir: str) -> None:
    """Unzip APK contents to destination directory."""
    if not os.path.isfile(apk_path):
        raise ApkError(f"APK file not found: {apk_path}")

    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            zf.extractall(dest_dir)
    except zipfile.BadZipFile as e:
        raise ApkError(f"Invalid ZIP/APK file: {e}") from e


def find_dex_files(extract_dir: str) -> list[str]:
    """Find all classes*.dex files in extracted APK directory.

    Returns sorted list: ['classes.dex', 'classes2.dex', 'classes3.dex', ...]
    """
    dex_pattern = re.compile(r"^classes(\d*)\.dex$")
    dex_files = []

    for entry in os.scandir(extract_dir):
        if entry.is_file():
            m = dex_pattern.match(entry.name)
            if m:
                num = int(m.group(1)) if m.group(1) else 1
                dex_files.append((num, entry.path, entry.name))

    if not dex_files:
        raise DexNotFoundError(
            f"No DEX files found in APK. Expected classes.dex, classes2.dex, etc."
        )

    # Sort by number and return paths
    dex_files.sort(key=lambda x: x[0])
    return [(path, name) for _, path, name in dex_files]


def verify_apk_structure(extract_dir: str) -> None:
    """Verify that extracted APK has the expected structure."""
    manifest = os.path.join(extract_dir, "AndroidManifest.xml")
    if not os.path.isfile(manifest):
        raise ApkError("AndroidManifest.xml not found in APK")

    # Verify at least one DEX exists
    find_dex_files(extract_dir)
