# Contributing

## Scope

This repository is maintained as a practical open-source core for Android APK protection workflows under the TriloApkGuard project name.

Contributions are welcome when they improve:

- correctness
- reproducibility
- compatibility
- diagnostics
- testability
- documentation

Contributions should not expand the public branch into a dump of future commercial-only hardening ideas without a clear maintainability plan.

## Before Opening A Change

- Read [README.md](README.md)
- Read [DISCLAIMER.md](DISCLAIMER.md)
- Keep the community/private boundary intact

In particular:

- public contributions should target the community core
- high-value proprietary key-management schemes should not be merged into the public branch by default

## Development Setup

Install editable dependencies:

```powershell
pip install -e .
```

Install development dependencies:

```powershell
pip install -e .[dev]
```

## Testing

Run unit tests:

```powershell
python -m pytest -q
```

Real-device testing is opt-in and requires Android tooling, a connected device, and Appium:

```powershell
$env:TRILODEX_REAL_DEVICE='1'
$env:TRILODEX_TEST_APK='output\protected.apk'
$env:TRILODEX_TEST_PACKAGE='com.example.app'
$env:TRILODEX_TEST_ACTIVITY='com.example.app.MainActivity'
python -m pytest tests\test_real_device_install_launch.py -q -s
```

Do not make the default test suite depend on a real device.

## Change Expectations

- Keep changes focused and explain the motivation clearly.
- Prefer additive interfaces over hard-coded commercial assumptions.
- Preserve or improve real-device verifiability.
- Avoid committing generated APKs, keystores, sample third-party APKs, or signing outputs.
- Do not weaken the public/private boundary in `key_management` without a strong reason.

## Documentation

Update documentation when changing:

- CLI behavior
- key-management boundaries
- runtime loading flow
- test commands
- required toolchain

## Pull Request Notes

Useful pull requests usually include:

- a short problem statement
- the chosen approach
- test coverage or reproduction steps
- compatibility impact if relevant
