"""Real-device smoke test for protected APK install and launch."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest
from appium import webdriver
from appium.options.android import UiAutomator2Options


PACKAGE_NAME = "com.gotenna.proag"
LAUNCH_ACTIVITY = "com.gotenna.proag.SplashActivity"
FOREGROUND_STATE = 4
SERVER_START_TIMEOUT = 30
APP_LAUNCH_TIMEOUT = 90

pytestmark = pytest.mark.real_device


def _env_enabled(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_apk() -> Path:
    configured = os.getenv("TRILODEX_TEST_APK")
    if configured:
        apk_path = Path(configured).expanduser().resolve()
    else:
        candidates = sorted(
            (_project_root() / "output").glob("*Signed.apk"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        if not candidates:
            raise FileNotFoundError(
                "No signed APK found under output/. Set TRILODEX_TEST_APK to an installable APK."
            )
        apk_path = candidates[0]

    if not apk_path.is_file():
        raise FileNotFoundError(f"APK not found: {apk_path}")
    return apk_path


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _resolve_appium_executable() -> str:
    configured = os.getenv("APPIUM_BIN", "").strip()
    if configured:
        return configured

    for candidate in ("appium.cmd", "appium"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved

    npm_shim = Path.home() / "AppData" / "Roaming" / "npm" / "appium.cmd"
    if npm_shim.is_file():
        return str(npm_shim)

    raise FileNotFoundError(
        "Appium executable not found. Set APPIUM_BIN or add appium.cmd to PATH."
    )


def _resolve_android_sdk_root() -> str:
    for name in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        configured = os.getenv(name, "").strip()
        if configured and Path(configured).is_dir():
            return configured

    for tool_name in ("aapt2", "aapt", "adb"):
        tool_path = shutil.which(tool_name)
        if not tool_path:
            continue

        path = Path(tool_path).resolve()
        if path.parent.name == "platform-tools":
            sdk_root = path.parent.parent
        elif path.parent.parent.name == "build-tools":
            sdk_root = path.parent.parent.parent
        else:
            continue

        if sdk_root.is_dir():
            return str(sdk_root)

    raise FileNotFoundError(
        "Android SDK root not found. Set ANDROID_HOME or ANDROID_SDK_ROOT."
    )


def _resolve_java_home() -> str:
    configured = os.getenv("JAVA_HOME", "").strip()
    if configured:
        java_home = Path(configured)
        if (java_home / "bin" / "java.exe").is_file() or (java_home / "bin" / "java").is_file():
            return str(java_home)

    java_path = shutil.which("java")
    if java_path:
        return str(Path(java_path).resolve().parent.parent)

    raise FileNotFoundError("Java runtime not found. Set JAVA_HOME or add java to PATH.")


def _adb(serial: str | None, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    cmd = ["adb"]
    if serial:
        cmd.extend(["-s", serial])
    cmd.extend(args)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(
            f"ADB command failed ({' '.join(cmd)}):\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def _resolve_serial() -> str:
    serial = os.getenv("ANDROID_SERIAL", "").strip()
    if serial:
        return serial

    result = _adb(None, "devices")
    devices = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])

    if not devices:
        raise RuntimeError("No Android device detected by adb.")
    return devices[0]


def _device_info(serial: str) -> dict[str, str]:
    model = _adb(serial, "shell", "getprop", "ro.product.model").stdout.strip()
    version = _adb(serial, "shell", "getprop", "ro.build.version.release").stdout.strip()
    sdk = _adb(serial, "shell", "getprop", "ro.build.version.sdk").stdout.strip()
    return {
        "serial": serial,
        "model": model or "unknown",
        "android_version": version or "unknown",
        "sdk": sdk or "unknown",
    }


def _ensure_package_removed(serial: str) -> None:
    listed = _adb(serial, "shell", "pm", "list", "packages", PACKAGE_NAME).stdout
    if f"package:{PACKAGE_NAME}" in listed:
        _adb(serial, "uninstall", PACKAGE_NAME)


def _install_apk(serial: str, apk_path: Path) -> None:
    result = _adb(serial, "install", "-r", "-g", str(apk_path), check=False)
    combined_output = f"{result.stdout}\n{result.stderr}"
    if result.returncode != 0 or "Success" not in combined_output:
        raise AssertionError(f"APK install failed for {apk_path}:\n{combined_output}")


def _wait_for_appium(server_url: str, timeout_seconds: int) -> None:
    deadline = time.time() + timeout_seconds
    last_error: Exception | None = None
    status_url = f"{server_url.rstrip('/')}/status"

    while time.time() < deadline:
        try:
            with urllib.request.urlopen(status_url, timeout=2) as response:
                payload = json.loads(response.read().decode("utf-8"))
            if payload.get("value", {}).get("ready", True):
                return
        except Exception as exc:  # pragma: no cover - environment-dependent
            last_error = exc
        time.sleep(1)

    raise RuntimeError(f"Appium server did not become ready: {last_error}")


@contextmanager
def _appium_server():
    external_url = os.getenv("APPIUM_SERVER_URL", "").strip()
    if external_url:
        yield external_url
        return

    port = _find_free_port()
    server_url = f"http://127.0.0.1:{port}"
    log_handle = tempfile.NamedTemporaryFile(
        prefix="trilodex_appium_", suffix=".log", delete=False
    )
    log_path = Path(log_handle.name)
    log_handle.close()
    log_stream = open(log_path, "w", encoding="utf-8")
    sdk_root = _resolve_android_sdk_root()
    java_home = _resolve_java_home()
    process_env = os.environ.copy()
    process_env["ANDROID_HOME"] = sdk_root
    process_env["ANDROID_SDK_ROOT"] = sdk_root
    process_env["JAVA_HOME"] = java_home
    process_env["PATH"] = os.pathsep.join(
        [
            str(Path(java_home) / "bin"),
            str(Path(sdk_root) / "platform-tools"),
            process_env.get("PATH", ""),
        ]
    )

    process = subprocess.Popen(
        [_resolve_appium_executable(), "--address", "127.0.0.1", "--port", str(port), "--base-path", "/"],
        stdout=log_stream,
        stderr=subprocess.STDOUT,
        text=True,
        env=process_env,
    )

    try:
        _wait_for_appium(server_url, SERVER_START_TIMEOUT)
        yield server_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - environment-dependent
            process.kill()
        log_stream.close()


def _wait_for_foreground(driver: webdriver.Remote) -> dict[str, int | str]:
    deadline = time.time() + APP_LAUNCH_TIMEOUT
    last_state = -1
    last_package = ""
    last_activity = ""

    while time.time() < deadline:
        last_state = driver.query_app_state(PACKAGE_NAME)
        last_package = driver.current_package
        last_activity = driver.current_activity
        if last_state == FOREGROUND_STATE and last_package == PACKAGE_NAME:
            return {
                "app_state": last_state,
                "current_package": last_package,
                "current_activity": last_activity,
            }
        time.sleep(1)

    raise AssertionError(
        "App did not stay in foreground after launch. "
        f"package={last_package}, activity={last_activity}, state={last_state}"
    )


def run_install_launch_smoke() -> dict[str, str | int]:
    apk_path = _resolve_apk()
    serial = _resolve_serial()
    device = _device_info(serial)

    _ensure_package_removed(serial)
    _install_apk(serial, apk_path)

    options = UiAutomator2Options().load_capabilities(
        {
            "platformName": "Android",
            "automationName": "UiAutomator2",
            "deviceName": serial,
            "udid": serial,
            "appPackage": PACKAGE_NAME,
            "appActivity": LAUNCH_ACTIVITY,
            "autoGrantPermissions": True,
            "adbExecTimeout": 120000,
            "androidInstallTimeout": 180000,
            "appWaitDuration": 90000,
            "newCommandTimeout": 180,
            "noReset": False,
        }
    )

    with _appium_server() as server_url:
        driver = webdriver.Remote(server_url, options=options)
        try:
            foreground = _wait_for_foreground(driver)
            installed = _adb(serial, "shell", "pm", "list", "packages", PACKAGE_NAME).stdout
            if f"package:{PACKAGE_NAME}" not in installed:
                raise AssertionError(f"Package was not installed: {PACKAGE_NAME}")

            return {
                "apk": str(apk_path),
                "serial": device["serial"],
                "model": device["model"],
                "android_version": device["android_version"],
                "sdk": device["sdk"],
                "current_package": str(foreground["current_package"]),
                "current_activity": str(foreground["current_activity"]),
                "app_state": int(foreground["app_state"]),
            }
        finally:
            driver.quit()


@pytest.mark.skipif(
    not _env_enabled("TRILODEX_REAL_DEVICE"),
    reason="Set TRILODEX_REAL_DEVICE=1 to run the real-device Appium smoke test.",
)
def test_can_install_and_launch_protected_apk():
    result = run_install_launch_smoke()
    assert result["current_package"] == PACKAGE_NAME
    assert result["app_state"] == FOREGROUND_STATE


def main() -> int:
    result = run_install_launch_smoke()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
