# Supplied macOS Keychain and iCloud Access Projection

The GC-D12-S12 partial component compares at most 64 synthetic Keychain or
iCloud access declarations with supplied app-to-store approvals. Separate
verification replays the original supplied model.

App IDs, store kinds, bindings, access, and completeness are unverified
assertions. No Keychain item, iCloud content, credential, or secret is read.
A binding mismatch does not prove unauthorized access or establish a finding.
The component grants no authority or qualification.

The checked synthetic example is
[`examples/offline-macos-store-access-component.json`](../examples/offline-macos-store-access-component.json).
