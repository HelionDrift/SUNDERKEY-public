# Offline Asset Lifecycle Review

This V9.2 companion compares two passive asset-reconciliation snapshots and
their exact caller-supplied observation sets. It retains a review row for every
asset in the prior snapshot, including assets that disappear from the current
snapshot. A missing asset is a tombstone review candidate, never a deletion or
an operational tombstone.

## Replay and Classification

`build_asset_lifecycle_review` first replays the prior snapshot from its
supplied observations, then replays the current snapshot with the prior as its
continuity source. For longer chains, the caller can provide the predecessor
of the prior snapshot. That predecessor is content-checked but its own source
history is not replayed by this function. The report binds both snapshot
digests, the optional predecessor digest, and the complete deterministic
classification under a domain-separated content address.

Each prior asset is classified as retained, identity reassigned, ambiguous
continuity, unobserved with a source-class gap, or unobserved despite source-
class overlap. A missing source class forces review even when the asset ID is
retained. Source-class overlap does not establish that a feed was complete.
`verify_asset_lifecycle_review` recomputes the exact report and rejects an
omitted or substituted supplied observation, a changed classification, an
extra field, duplicate JSON keys, or a changed no-effects declaration.

## Safety Boundary

The report never retires an asset. Every unobserved asset requires independent
review and explicit authoritative lifecycle evidence before any operational
inventory changes. The module does not authenticate the supplied source
records or prove they comprise every real-world observation. It does not
collect data, probe a target, schedule work, route an expert, qualify a
runtime, or grant authority. The checked schema is
[`asset-lifecycle-review-v1.schema.json`](../registry/schemas/asset-lifecycle-review-v1.schema.json).

This closes the repository-only disappearance review gap in the Phase 208
reconciliation contract. Production tombstone publication, source
authentication, signed owner disposition, and anti-rollback custody remain
separate work.
