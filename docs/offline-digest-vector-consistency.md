# Supplied Digest Vector Consistency

The GE-D22-S14 partial component compares at most 32 declared synthetic,
unkeyed digest vectors against local Python reference calculations for SHA-256,
SHA3-256, and SHA-512. Each input is bounded to 256 bytes. The report lists
matching and mismatching vector IDs without copying input bytes or claimed
digests into the output. Separate verification replays the original model.

This is a narrow known-answer consistency check. Fixture status, vector
completeness, and claimed outputs are caller-supplied assertions. It does not
execute the claimed implementation, verify an implementation, perform practical
cryptanalysis, or contact a target. It accepts no credential references or
keyed vectors; the caller must supply synthetic input bytes only. A mismatch is not a
finding or an exploit. The component grants no qualification or action authority.

The checked synthetic example is
[`examples/offline-digest-vector-component.json`](../examples/offline-digest-vector-component.json).
