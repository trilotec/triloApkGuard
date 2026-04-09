# Disclaimer

## Intended Use

TriloApkGuard is provided for research, evaluation, internal tooling, and protection workflows applied to APKs that you own or are explicitly authorized to process.

Do not use this repository, its code, or its build pipeline against third-party applications unless you have clear legal and contractual permission to do so.

## Community Edition Boundary

The public repository is intentionally limited to a community key-management scheme and a public protection core.

The public branch is intended to provide:

- a usable end-to-end APK protection pipeline
- reproducible packaging behavior
- real-device install and launch validation
- a stable extension point for future private implementations

The public branch is not intended to publish or guarantee:

- hardened commercial key-management designs
- advanced anti-analysis-aware key recovery
- universal protection against reverse engineering
- enterprise-grade support commitments

## Compatibility And Security Limits

Android protection features are inherently compatibility-sensitive.

Behavior may vary across:

- Android versions
- vendor ROMs
- ABI targets
- target application structure
- third-party SDK initialization behavior

Even when a protected APK builds successfully, runtime regressions are still possible. Real-device validation is necessary for every meaningful target.

## No Security Guarantee

This project should not be described or relied on as providing absolute protection.

It may raise reverse-engineering cost for some scenarios, but no public representation in this repository should be interpreted as a guarantee that an APK cannot be analyzed, instrumented, dumped, modified, or repackaged.

## Commercial Separation

Future commercial editions may extend this repository through stronger key management, hardened native storage, anti-analysis features, compatibility layers, and operational tooling.

Those capabilities are intentionally outside the scope of the public branch.

## Repository Hygiene

If you publish this repository, do not include:

- third-party APK samples
- generated protected APKs
- signing artifacts
- private keys or keystores
- customer-specific policies or proprietary key-management material
