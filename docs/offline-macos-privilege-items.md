# Supplied macOS Privileged-Item Projection

The GC-D12-S09 partial component compares at most 64 synthetic launch daemon,
privileged helper, or startup-item declarations. It marks an item when both
root execution and user-writable placement are declared. Separate
verification replays the original supplied model.

Item kinds, permissions, execution contexts, and completeness are unverified
assertions. No launchd item or file permission is inspected, and no item is
executed. A declared overlap does not prove privilege escalation or establish
a finding. It grants no authority or qualification.

The checked synthetic example is
[`examples/offline-macos-privilege-items-component.json`](../examples/offline-macos-privilege-items-component.json).
