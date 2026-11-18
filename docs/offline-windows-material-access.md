# Supplied Windows Protected-Material Access Projection

The GC-D11-S11 partial component compares at most 64 synthetic LSASS-memory
or DPAPI-protected-blob access declarations with a supplied approval list.
Separate verification replays the original supplied model.

The inventory, access declarations, approvals, and completeness are unverified
assertions. No process memory, protected blob, or secret value is accepted or
read. An approval mismatch is a review signal, not proof of credential access
or a vulnerability finding. No host, process, credential, or target is
accessed, and no authority or qualification is granted.

The checked synthetic example is
[`examples/offline-windows-material-access-component.json`](../examples/offline-windows-material-access-component.json).
