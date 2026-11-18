# Supplied Mobile Distribution Consistency Projection

The GB-D08-S14 partial component compares at most 64 synthetic release
assignments with at most 32 declared channels and 64 releases. It reports
missing release references, channel mismatches, builds below a declared
minimum, and signers that differ from a declared channel digest. The report
retains cohort, channel, and release IDs and flags, but not signer digests.
Separate verification replays the original model.

All channels, releases, signer digests, minimum builds, assignments, and
inventory-completeness claims are supplied assertions. The projection does
not validate an app package, certificate, device, or MDM state, and it cannot
prove a distribution weakness. It performs no target interaction, grants no
authority, and has no qualification effect.

The checked synthetic example is
[`examples/offline-mobile-distribution-component.json`](../examples/offline-mobile-distribution-component.json).
