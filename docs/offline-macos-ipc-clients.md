# Supplied macOS IPC-Client Policy Projection

The GC-D12-S13 partial component compares at most 64 synthetic XPC or Apple
Events interfaces with supplied approved and declared client IDs. It marks
declared clients outside the supplied policy. Separate verification replays
the original supplied model.

Interfaces, clients, approvals, and completeness are unverified assertions.
No IPC identity enforcement is verified, no message is sent, and no host is
contacted. A client mismatch does not prove unauthorized access or establish
a finding. It grants no authority or qualification.

The checked synthetic example is
[`examples/offline-macos-ipc-clients-component.json`](../examples/offline-macos-ipc-clients-component.json).
