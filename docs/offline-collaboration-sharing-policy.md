# Supplied Collaboration-Sharing Policy Projection

The GC-D11-S16 partial component compares at most 64 synthetic document,
site, and team sharing declarations with caller-supplied share-mode policies.
It flags declared modes absent from the corresponding policy. Separate
verification replays the original supplied model.

Resources, modes, policies, and completeness are unverified assertions. The
abstract labels are not parsed or verified Microsoft 365 sharing controls.
The component does not connect to a tenant, read a document, change a share,
or contact a target. A mismatch does not prove public access or data
exposure. It cannot grant authority, publish a finding, or qualify the
specialist. Office add-ins and macros remain outside this first partial model.

The checked synthetic example is
[`examples/offline-collaboration-sharing-component.json`](../examples/offline-collaboration-sharing-component.json).
