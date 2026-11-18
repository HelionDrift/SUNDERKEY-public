# Supplied backup chain projection

The `AOE-GB-D07-S13` partial specialist projects a caller-supplied full or
incremental snapshot chain against integer-tick restore-point objectives. It
requires every declared parent to be an older supplied snapshot, and excludes
a chain if any member is expired at the declared assessment tick or marked not
restorable. It reports the best supplied chain and lag, or distinguishes a
complete from an incomplete supplied history when no chain is present.

The exact native JSON model declares `schema_version: 1`,
`semantics_profile: supplied-backup-chain-v1`, an opaque dataset reference,
assessment tick, history-completeness assertion, up to 256 snapshots, and 1 to
16 objectives. Ticks are abstract integers, not timestamps. The typed report
replays from the bounded model.

Snapshot records, expiry, parentage, and declared restorability are
unauthenticated caller statements. No backup bytes, retention policy, or
successful restore are verified. No storage, provider, service, credential,
network, or target is contacted. The report grants no action authority or
qualification. The [synthetic example](../examples/offline-backup-chain-component.json)
uses only fictitious opaque references.
