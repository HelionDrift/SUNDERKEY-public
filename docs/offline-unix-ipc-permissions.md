# Supplied BSD and Unix IPC Permission Projection

The GC-D12-S14 partial component compares at most 64 synthetic Unix-domain
socket or named-pipe declarations. It marks an artifact when both privileged
service ownership and world-writable access are declared. Separate
verification replays the original supplied model.

Artifacts, service privilege, permissions, and completeness are unverified
assertions. No BSD or Unix host is inspected, no IPC endpoint is connected,
and no credential is used. A declared overlap does not prove access or
impact. It is not a finding and grants no authority or qualification.

The checked synthetic example is
[`examples/offline-unix-ipc-permissions-component.json`](../examples/offline-unix-ipc-permissions-component.json).
