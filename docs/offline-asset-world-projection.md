# Offline Asset-to-World Projection

`offline_asset_world_projection.py` maps a source-replayed passive asset
reconciliation snapshot into a new, planning-only attack world snapshot. It
creates asset nodes only. Every node is a zero-confidence `hypothesis` backed
by the caller-supplied reconciliation snapshot digest. It creates no edge,
verified path, finding, target authority, action admission, or qualification.

## Required Sources

`project_offline_assets_to_world` requires the typed reconciliation snapshot,
its complete raw `AssetObservation` tuple, a bounded `scope:` label, and a
caller-supplied UTC projection time. If the snapshot has predecessors, pass
every predecessor as `(snapshot, raw_observation_tuple)` in oldest-to-newest
order through `prior_sources`. The module replays the complete source chain
before producing any packet. It rejects a missing predecessor, a changed raw
observation set, a coherent substitute snapshot, and inconsistent lineage.

The projection time must be at or after the current snapshot time and no more
than 24 hours later. It is a caller declaration, not a trusted clock. The
`scope:` label is likewise a caller declaration, not evidence that an asset is
inside an authorized target scope.

## Withheld Assets

An asset with any unresolved reconciliation conflict is withheld. A stale
asset, or one with no provenance still current at the projection time, is also
withheld. The packet lists only opaque asset IDs and fixed reason codes for
withheld assets. Projected node labels contain only the opaque asset ID, not
source claims, owner names, addresses, or raw observation contents.

Projected evidence expires at the earliest active source expiry, capped at 24
hours after the supplied projection time. That expiry bounds a planning
hypothesis. It does not authenticate the source or prove that the asset still
exists. A later snapshot requires a fresh projection, not an append that keeps
old nodes alive.

## Replay and Limits

`verify_offline_asset_world_projection` requires the separate original
snapshot, raw observations, lineage, scope label, and projection time. It
rebuilds and compares the entire packet. A self-consistent packet hash alone
is not verification. The packet binds the snapshot digest and the digest and
count of each raw observation set. Input is capped at 256 assets, 4,096 raw
observations across at most eight prior snapshots, and exact typed records.
Packet traversal is bounded by 1 MiB, 65,536 native nodes, and depth 24.
Canonical raw-source hashing has a 16 MiB aggregate byte ceiling across the
entire supplied lineage.

The packet declares no operational effects. `positive_use_approved`,
`source_authenticated`, `scope_equivalence_proven`,
`verified_path_created`, and `qualification_claimed` are always false. This
component reads no files and makes no network, provider, target, credential,
process, publication, or deployment call. Production consumers must obtain
independent live authority and trusted current evidence before any positive
action.
