# Supplied Vendor Update Lineage

`AOE-GC-D17-S14` has one partial, inert update-lineage projection. It compares
an operator-selected prior release to supplied offers in the same declared
channel. It flags lower metadata or release versions, a changed artifact
digest at the same release version, and metadata expiration relative to a
supplied observation time. Offers in another channel remain incomparable.

The [TUF metadata overview](https://theupdateframework.io/docs/metadata/)
describes versioned and hashed update metadata. This local model is not a TUF
client. It does not parse or validate TUF metadata, signatures, keys,
delegations, thresholds, or trusted roots. Its integers, digests, channels,
and time are caller assertions.

## Input Boundary

The model has exactly `schema_version`, `source_id`, `inventory_complete`,
`observed_at`, `trusted`, and `offers`. Each release row contains a channel ID,
release version, artifact SHA-256 label, and metadata version. Each offer also
has an offer ID and expiration time. Times must be second-resolution UTC.
No artifact bytes, signatures, public keys, credentials, update payloads,
network addresses, or target identities are accepted. Unknown fields fail
closed.

The `trusted` row is only an operator-selected comparison baseline. The name
does not mean that SUNDERKEY has authenticated it. The supplied observation
time is not a trusted clock. A rollback or divergence signal is a declared
metadata conflict, not proof that a vendor served it, that a client accepted
it, or that compromise occurred. A clean comparison does not prove channel
or software safety.

The synthetic example supplies an older, expired offer in the same channel.
The report is content-addressed and independently replayed from the original
model. It is unsigned and nonqualifying. No release is fetched or installed,
no finding is published, and no live authority is issued. Actual metadata
verification, artifact measurement, vendor observation, independent review,
and qualification remain separate work.
