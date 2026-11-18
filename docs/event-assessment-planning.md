# Event assessment planning

This repository-only V9.3 slice turns supplied, typed change evidence into
bounded human-review candidates. It accepts an API release delta or attack-
surface drift assessment, or a matrix-bound API release review. The source
evidence is retained by SHA-256 lineage,
and each normalized event, candidate, and batch has a deterministic content
digest. It performs no event collection, target interaction, scheduling,
notification, authority change, or execution.
The no-effects declaration is immutable inside the module, and each serialized
batch receives its own effects object so a caller cannot alter later results
through an earlier returned dictionary.

`event_from_evidence` requires a post-release observation time for a release
delta. Drift event time comes from the assessment itself. A release ID can
produce distinct events as later observation windows change; identical event
content is deduplicated. All events and prior candidates must carry the exact
same scope digest, and future timestamps are rejected.

A [matrix-bound release review](api-release-role-response-review.md) retains the
`api_release_delta` event kind but binds its own review digest. Its explicit
event time must be at or after the current inventory snapshot, not merely after
the release. Newly observed role/status associations can produce a review
candidate even when the independent endpoint role and status sets are unchanged.
Missing-only associations remain inconclusive and create no change signal
unless the separately bound legacy delta already requires review. Existing
inventory-only release and drift event bytes and time rules are unchanged.

`plan_event_assessments` applies, in order, a stop switch, event freshness,
change-signal check, exact-event deduplication, per-scope cooldown, and a
rolling 24-hour candidate budget. The output dispositions are
`review_candidate`, `no_change_signal`, `duplicate`, `cooldown_suppressed`,
`budget_suppressed`, `stop_suppressed`, or `stale_evidence`. Inputs are bounded
to 256 events and 4,096 prior candidates. The daily budget has a hard ceiling
of 64. A candidate means only that evidence should be considered by a human
or separately governed policy workflow. It does not admit a run.
An event is permanently deduplicated only after it produces a review
candidate. A prior stop, cooldown, budget, or stale disposition does not
consume it. The same event may be reconsidered in a later batch if it remains
fresh and the suppressing condition has cleared. Repeated fresh copies inside
one active batch are still deduplicated.

`verify_assessment_candidate_batch` recomputes a stored batch from the exact
source events and prior-candidate history. It rejects a self-hashed batch that
omits a supplied event, changes a stop disposition, or is replayed with a
different cooldown or budget history. The batch now binds sorted, duplicate-
preserving digests of its complete event set and prior-candidate set. A
different prior history is rejected even if it happens to produce the same
candidate dispositions. This is historical consistency over
caller-supplied inputs, not authentication of the source or permission to run.

The caller remains responsible for authenticating the source system and
validating live authority before any positive admission or execution. This
module does not persist deduplication state by itself. The separate
`OfflineEventAssessmentHistoryStore` preserves and replays a complete local
history, as described in `docs/event-assessment-history.md`. Direct planner
callers must still supply a complete, trustworthy prior-candidate history for
the chosen cooldown and budget windows. Missing history can undercount prior
work, so no output should be used as an authorization or production scheduling
decision. Live authenticated intake, durable delivery, idempotent scheduler
integration, runner qualification, and stop propagation remain infrastructure
and integration work.
