"""External tool detection and management."""

import os
import shutil
import subprocess
from dataclasses import dataclass


class ToolNotFoundError(Exception):
    pass


@dataclass
class ToolStatus:
    java: str | None = None
    smali_jar: str | None = None
    aapt2: str | None = None
    zipalign: str | None = None
    apksigner: str | None = None
    ndk_clang: str | None = None

    def missing(self) -> list[str]:
        """Return list of missing tool names."""
        missing = []
        for name in ("java", "smali_jar", "aapt2", "zipalign", "apksigner", "ndk_clang"):
            if getattr(self, name) is None:
                missing.append(name.replace("_", " "))
        return missing

    def all_available(self) -> bool:
        return not self.missing()


def _find_executable(name: str, sdk_dir: str | None = None, subdir: str | None = None) -> str | None:
    """Find an executable in PATH or under SDK directory."""
    # Check PATH first
    path = shutil.which(name)
    if path:
        return path

    # Check under SDK directory
    if sdk_dir:
        if subdir:
            candidate = os.path.join(sdk_dir, subdir, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
            # Try .exe on Windows
            if os.name == "nt":
                candidate_exe = candidate + ".exe"
                if os.path.isfile(candidate_exe) and os.access(candidate_exe, os.X_OK):
                    return candidate_exe
        # Also check top-level
        candidate = os.path.join(sdk_dir, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def _find_smali_jar() -> str | None:
    """Find or download smali.jar."""
    # Check environment variable
    env_path = os.environ.get("SMALI_JAR")
    if env_path and os.path.isfile(env_path):
        return env_path

    # Check cache directory
    cache_dir = os.path.join(os.path.expanduser("~"), ".trilodex")
    os.makedirs(cache_dir, exist_ok=True)

    # Look for any smali-*.jar in cache
    for entry in os.scandir(cache_dir):
        if entry.name.startswith("smali-") and entry.name.endswith(".jar"):
            return entry.path

    return None


def _find_ndk_clang(sdk_dir: str | None = None) -> str | None:
    """Find NDK clang compiler."""
    if sdk_dir:
        ndk_dir = os.path.join(sdk_dir, "ndk")
        if os.path.isdir(ndk_dir):
            # Find latest NDK version
            versions = sorted(os.listdir(ndk_dir), reverse=True)
            for ver in versions:
                # Check for prebuilt clang
                prebuilt = os.path.join(ndk_dir, ver, "toolchains", "llvm", "prebuilt")
                if os.path.isdir(prebuilt):
                    # Find host-specific subdir
                    for host in os.scandir(prebuilt):
                        if host.is_dir():
                            bin_dir = os.path.join(host.path, "bin")
                            for ext in ("", ".exe", ".cmd", ".bat"):
                                clang = os.path.join(bin_dir, "clang" + ext)
                                if os.path.isfile(clang):
                                    return clang
    return None


def check_tools(sdk_dir: str | None = None, required: list[str] | None = None) -> ToolStatus:
    """Check availability of external tools.

    Args:
        sdk_dir: Android SDK root directory
        required: List of required tools. None = check all.
            Options: java, smali_jar, aapt2, zipalign, apksigner, ndk_clang
    """
    status = ToolStatus()

    # Java
    status.java = shutil.which("java")

    # Smali jar
    status.smali_jar = _find_smali_jar()

    # SDK tools
    build_tools_dir = _find_build_tools_dir(sdk_dir)
    if build_tools_dir:
        status.aapt2 = _find_executable("aapt2", build_tools_dir)
        status.zipalign = _find_executable("zipalign", build_tools_dir)
        status.apksigner = _find_executable("apksigner", build_tools_dir)

    # NDK clang
    status.ndk_clang = _find_ndk_clang(sdk_dir)

    # Check required tools
    if required:
        missing = []
        for tool in required:
            if getattr(status, tool) is None:
                missing.append(tool)
        if missing:
            raise ToolNotFoundError(f"Required tools not found: {', '.join(missing)}")

    return status


def _find_build_tools_dir(sdk_dir: str | None) -> str | None:
    """Find the latest Android SDK build-tools directory."""
    if not sdk_dir:
        return None

    bt_dir = os.path.join(sdk_dir, "build-tools")
    if not os.path.isdir(bt_dir):
        return None

    # Return latest version
    versions = sorted(os.listdir(bt_dir), reverse=True)
    if versions:
        return os.path.join(bt_dir, versions[0])

    return None
