# Supplied Mobile Storage-Control Projection

The GB-D08-S10 partial component compares at most 64 synthetic, caller-declared
storage artifacts with at most 32 declared policies. It reports only missing
control keys where the declared policy requires encryption at rest, backup
exclusion, or user presence and the supplied artifact state says otherwise.
Artifact IDs, policy IDs, storage categories, and declared data classes remain
in the report. No stored data or key material enters the model. Separate
verification replays the original model.

Policy requirements, inventory completeness, and control states are unverified
assertions. A mismatch is not a finding. The component does not inspect an
application or device, verify cryptography or biometrics, test backup behavior,
contact a target, grant authority, or qualify a specialist.

The checked synthetic example is
[`examples/offline-mobile-storage-component.json`](../examples/offline-mobile-storage-component.json).
