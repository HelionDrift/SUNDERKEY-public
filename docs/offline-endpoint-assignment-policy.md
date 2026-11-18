# Supplied Endpoint Assignment-Policy Projection

The GC-D11-S18 partial component compares at most 64 synthetic package
assignments with caller-supplied deployment-ring policies. It flags enabled
assignments outside a package's allowed rings. Separate verification replays
the original supplied model.

Packages, rings, assignments, and completeness are unverified assertions.
This component does not parse or verify SCCM or Intune configuration, connect
to a management service or device, read a package, or deliver software. A
declared mismatch does not establish installation or device impact. It cannot
grant authority, publish a finding, or qualify the specialist.

The checked synthetic example is
[`examples/offline-endpoint-assignment-component.json`](../examples/offline-endpoint-assignment-component.json).
