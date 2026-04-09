# Open-Source Release Checklist

## Repository Hygiene

- Remove third-party APK samples before publishing.
- Remove generated protected APKs and signing outputs.
- Ensure no private keystores or proprietary policies remain in the repository.
- Confirm `.gitignore` blocks APK outputs, idsig files, caches, and samples.

## Legal

- Confirm [LICENSE](f:/projects/triloDexPack/LICENSE) matches the intended public release policy.
- Review [DISCLAIMER.md](f:/projects/triloDexPack/DISCLAIMER.md).
- Verify no redistributed third-party binaries are included without permission.

## Documentation

- Review [README.md](f:/projects/triloDexPack/README.md).
- Review [CONTRIBUTING.md](f:/projects/triloDexPack/CONTRIBUTING.md).
- Review [SECURITY.md](f:/projects/triloDexPack/SECURITY.md).
- Confirm the community/private boundary remains accurate.

## Verification

- Run `python -m pytest -q`.
- Run at least one real-device smoke test before tagging a release.
- Confirm the CLI help and basic usage examples still work.

## Positioning

- Confirm the public branch still exposes only the intended community key scheme.
- Confirm no future commercial-grade key-management logic has leaked into the public branch.
