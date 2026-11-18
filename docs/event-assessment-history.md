# Offline event assessment history

The local event assessment history store preserves the complete sequence of
caller-supplied planning requests and their deterministic candidate batches.
It closes the planner's local prior-history omission gap across process
restarts. It does not authenticate a source, schedule an assessment, notify a
person, authorize a target, or execute any action.

## Durable sequence

`OfflineEventAssessmentHistoryStore` requires an explicit SQLite path and one
scope digest. Initialization creates a fixed version 1 schema and a genesis
hash. Each append runs in one immediate transaction. Before adding an entry,
the store checks the exact schema, metadata, sequence, content addresses, and
source replay of every existing batch. A new entry binds its request, prior
entry digest, batch digest, and monotonically increasing sequence. The head
sequence and digest are updated in the same transaction.

A request ID is an idempotency key. Repeating the exact request returns its
original batch without adding an entry. Reusing that ID for different inputs
fails closed. Concurrent identical submissions serialize to one entry. New
requests cannot move assessment time backward. The store derives prior
candidates from its own verified history, not from a caller-provided list.

Only candidates within the maximum relevant event-age, cooldown, or daily
budget window are passed to the planner. Older records remain in the journal
for replay but cannot affect a later valid request. The planner's limit of
4,096 active prior candidates, 16,384 journal entries, and a 128 MiB database
file fail closed rather than silently omitting history. An operator must use a separate
reviewed archival and anchoring design before those limits are reached.

## Verification and limits

Read-only verification replays every recorded request against the prior
verified candidates. It rejects edited batch JSON, changed request inputs,
schema additions, sequence gaps, deleted tail entries, or a head that no
longer matches the chain. The file is not a cryptographic authority root.
Someone who can rewrite the entire database, including its head, may forge a
new self-consistent history. Production anti-rollback custody requires an
independent signed or externally anchored head and platform access controls.

The journal stores only typed event metadata and opaque evidence digests. It
does not contain captured target payloads, credentials, network clients,
target adapters, a scheduler, or an execution path. SQLite here is a local
offline reference store, not a D014 production database selection or a claim
of deployment or qualification.
