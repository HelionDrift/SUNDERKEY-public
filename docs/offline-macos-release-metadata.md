# Supplied macOS Release Metadata Projection

The GB-D08-S16 partial component compares at most 64 synthetic, supplied
release records with a caller-declared baseline for bundle ID, team ID,
minimum build, and required and allowed entitlement IDs. It reports only
baseline differences and set differences. Separate verification replays the
original model.

These are metadata assertions, not parsed package contents or macOS security
semantics. A matching team ID or entitlement list does not verify a signature,
effective entitlement, notarization, or platform policy. A deviation is not
a vulnerability finding. The component does not inspect an app or macOS host,
contact a target, grant authority, or qualify a specialist.

The checked synthetic example is
[`examples/offline-macos-release-component.json`](../examples/offline-macos-release-component.json).
