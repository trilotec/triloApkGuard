# TriloApkGuard

TriloApkGuard is a practical Android APK protection core with real-device validation.

It takes an input APK, encrypts its DEX payloads, injects a runtime stub, rebuilds and signs the APK, and verifies that the protected artifact can still install and launch on a physical Android device.

See also:

- [DISCLAIMER.md](f:/projects/triloDexPack/DISCLAIMER.md)
- [CONTRIBUTING.md](f:/projects/triloDexPack/CONTRIBUTING.md)
- [SECURITY.md](f:/projects/triloDexPack/SECURITY.md)

## What It Does

- Protects `classes*.dex` files and stores encrypted payloads inside the APK.
- Injects a runtime stub that restores the protected code path at app startup.
- Rebuilds, aligns, and signs the protected APK.
- Supports multi-dex APKs.
- Includes a real-device smoke test for install and launch validation.

## Current Implementation

The current open-source implementation is not a pure managed-code stub.

It already uses a small native component:

- A generated `libtrilocfg.so` stores part of the runtime key material.
- The injected stub loads the native library and reconstructs the runtime seed before decrypting protected DEX files.
- The current stub is implemented with smali and uses Android runtime loading APIs to restore the application code path.

The public repository now treats this as a deliberate community boundary:

- The public branch ships a basic, inspectable key strategy through `CommunityKeyManager`.
- The public goal is end-to-end correctness and real-device validation, not publication of a future commercial-grade key-management design.
- More advanced key-management schemes should live behind the same interface in private or commercial extensions.

## Project Scope

### Community Edition

The open-source version is intended to provide a stable, understandable protection core:

- APK parsing and repackaging
- DEX encryption and runtime loading
- Manifest patching
- Signing and alignment
- Basic native key storage through the public community key scheme
- Real-device install and launch validation
- Compatibility maintenance and bug fixes

### Commercial Direction

The long-term commercial direction is intended for higher-cost protection features and enterprise workflows, for example:

- stronger `so` protection
- resource encryption
- anti-debugging
- anti-hook / anti-dump
- root / virtual environment / multi-instance detection
- hardened key management and dynamic key policy
- batch processing and enterprise integration

The community edition should remain usable on its own. Commercial work should extend the core rather than replace it.

## Repository Layout

- [trilo_dex](f:/projects/triloDexPack/trilo_dex): core Python implementation
- [trilo_dex/key_management.py](f:/projects/triloDexPack/trilo_dex/key_management.py): public key-management interface and community implementation
- [stub](f:/projects/triloDexPack/stub): injected smali runtime stub
- [native](f:/projects/triloDexPack/native): native code generation inputs
- [tests](f:/projects/triloDexPack/tests): unit tests and real-device smoke test

## Requirements

- Python 3.10+
- Java
- Android SDK build-tools
- `smali.jar`
- Android NDK if building the native library
- `adb` for device validation
- Appium + `uiautomator2` driver for the real-device smoke test

Python dependencies are defined in [pyproject.toml](f:/projects/triloDexPack/pyproject.toml).

The code package remains `trilo_dex` for now, while the public project name is `TriloApkGuard`.

## Quick Start

Install the package in editable mode:

```powershell
pip install -e .
```

Protect an APK:

```powershell
python -m trilo_dex.cli input.apk -o output\protected.apk --sdk-dir D:\AndroidSdk -v
```

Or use the CLI entry point:

```powershell
triloapkguard input.apk -o output\protected.apk --sdk-dir D:\AndroidSdk -v
```

## Real-Device Validation

Run unit tests:

```powershell
python -m pytest -q
```

Run the real-device install-and-launch smoke test:

```powershell
$env:TRILODEX_REAL_DEVICE='1'
$env:TRILODEX_TEST_APK='F:\projects\triloDexPack\output\protected.apk'
$env:TRILODEX_TEST_PACKAGE='com.example.app'
$env:TRILODEX_TEST_ACTIVITY='com.example.app.MainActivity'
python -m pytest tests\test_real_device_install_launch.py -q -s
```

The real-device test:

- installs the APK with `adb`
- starts an Appium `uiautomator2` session
- launches the target app
- verifies that the app reaches the foreground

The real-device smoke test does not ship with a hard-coded third-party package name. Set
`TRILODEX_TEST_PACKAGE` and `TRILODEX_TEST_ACTIVITY` for the APK under test.

See [tests/test_real_device_install_launch.py](f:/projects/triloDexPack/tests/test_real_device_install_launch.py).

## Design Notes

At a high level, the current flow is:

1. Extract APK contents.
2. Locate `classes*.dex`.
3. Generate runtime key material through the active key manager.
4. Encrypt DEX payloads.
5. Build `libtrilocfg.so`.
6. Inject the stub as the new entry DEX.
7. Patch `AndroidManifest.xml`.
8. Repackage, align, and sign the APK.
9. Validate installation and startup on a device.

## Intended Audience

This repository is mainly useful for:

- engineers researching Android protection workflows
- developers building custom APK hardening pipelines
- teams evaluating a practical open-core foundation for later commercial extensions

## Public Vs Private Boundary

The repository intentionally exposes a public key-management interface while keeping the shipped strategy basic:

- `KeyManager` is the extension point.
- `CommunityKeyManager` is the public implementation used by default.
- The community scheme is intended to keep the pipeline usable and testable.
- Stronger proprietary key recovery, dynamic policy, and anti-analysis-aware schemes should plug into the same interface outside the public branch.

## Legal And Operational Notes

- Use this project only on APKs you own or are explicitly authorized to process.
- Do not commit third-party APK samples, signed outputs, or private signing assets into a public repository.
- Protection features always have compatibility risk across apps, ROMs, Android versions, and vendor customizations.
- The open-source version should be treated as a practical core, not as a guarantee of universal compatibility or absolute resistance to reverse engineering.
- See [DISCLAIMER.md](f:/projects/triloDexPack/DISCLAIMER.md) for the intended public boundary of the repository.

## Status

This project is currently positioned as an open-source core with room for future commercial extensions.

The public branch should prioritize:

- correctness
- reproducibility
- compatibility maintenance
- testability on real devices

If you are evaluating the repository, the most important question is not whether it contains every advanced defense today, but whether the core pipeline is clean, inspectable, and verifiable end to end.
