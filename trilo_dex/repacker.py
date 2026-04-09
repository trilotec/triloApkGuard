"""APK repackaging (ZIP with correct compression modes)."""

import os
import zipfile


# Files that must be stored (not compressed) in APK
STORED_EXTENSIONS = {".dex", ".arsc", ".xml", ".so"}
STORED_EXACT = {"AndroidManifest.xml"}

# Directories to exclude
EXCLUDE_DIRS = {"META-INF"}


def repackage_apk(extract_dir: str, output_apk: str) -> None:
    """Repackage extracted APK directory into a new ZIP file.

    Uses STORED for .dex/.arsc/.xml files, DEFLATED for everything else.
    Excludes META-INF/ directory.
    """
    with zipfile.ZipFile(output_apk, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(extract_dir):
            # Exclude directories
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

            # Sort for deterministic output
            for fname in sorted(files):
                full_path = os.path.join(root, fname)
                arcname = os.path.relpath(full_path, extract_dir)

                # Normalize path separators to forward slashes (ZIP standard)
                arcname = arcname.replace(os.sep, "/")

                # Determine compression mode
                if _should_store(arcname):
                    zf.write(full_path, arcname, compress_type=zipfile.ZIP_STORED)
                else:
                    zf.write(full_path, arcname, compress_type=zipfile.ZIP_DEFLATED)


def _should_store(arcname: str) -> bool:
    """Check if a file should use STORED (no compression)."""
    # Exact match
    if arcname in STORED_EXACT:
        return True

    # Extension match
    _, ext = os.path.splitext(arcname)
    if ext.lower() in STORED_EXTENSIONS:
        return True

    return False
