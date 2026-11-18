# Offline Change-to-Retest Review

`stage_change_retest_review` composes a typed change event, durable candidate
history, a current scope-authority check, and optional finding and schedule
bindings. It produces a content-addressed packet for human review only.

The composition has one local write: an atomic append to
`OfflineEventAssessmentHistoryStore`. A repeat with the same request ID and
identical inputs replays the stored candidate. A new request for the same
event is recorded as a duplicate and does not produce another review packet.
After restart, `verify_change_retest_review_history` replays the full chain
and returns only the packet's request-to-candidate linkage. The packet binds
its original history entry, not a mutable global head, so a later append does
not strand the earlier request. The returned link does not authenticate the
packet's tenant, authority, finding, or schedule fields. The packet hash is
unsigned and can be recomputed by a caller. A historical candidate link is
not current authority and cannot be used for a positive action.

## Injected Trust Requirements

The caller supplies separate implementations of `TrustedClock`,
`CurrentSourceVerifier`, and `CurrentAuthorityVerifier`. A finding association
also requires a separate `FindingBindingVerifier`. These ports must be backed
by independent trusted data and must be evaluated for each invocation.
This repository does not provide production trust roots or network collectors
for those ports. The event and packet cannot verify their own source or
authority. Matching a digest alone is not proof that a verifier is trustworthy.

The source verifier must bind the complete typed event to original current
source evidence. The authority verifier must check the tenant, scope, purpose,
and trusted evaluation time. The optional finding verifier must establish that
the current `retest_pending` snapshot belongs to the change event. The module
replays the snapshot and schedule structures and rejects stale schedule
authority, a foreign tenant or scope, an absent finding verifier, and a
suppressed candidate. It does not infer a finding-to-scope link from text.

## Effect Boundary

The packet has `conditional_human_review_only` status and no qualification,
admission, execution, publication, scheduler activation, finding transition,
or target-interaction effect. It does not create a `RetestPlan`, materialize a
durable schedule occurrence, run an assessment, observe a retest result, or
update a finding. Every later positive use needs current authority and source
checks again. This bridge is an offline composition seam, not a production
change-to-retest execution loop.

## Conditional Currentness Revalidation

`verify_change_retest_review_current` is a separate, read-only check for an
existing packet. It first verifies the durable historical candidate, then
compares independently supplied original event, tenant, finding, and schedule
objects against the packet. Recomputing the unsigned packet hash cannot make
an altered tenant, finding, schedule, or authority original pass this check.

The caller must inject distinct time, source-lineage, and scope-authority
receipt verifiers. A packet with a finding or schedule additionally requires
separate current finding or schedule receipt verifiers. The time receipt binds
the exact packet and event to a checked instant no earlier than packet staging.
Every other receipt binds that same packet, event, and instant. Source lineage
must explicitly claim completeness, no conflict, and no supersession; matching
the old evidence digest alone is insufficient. It also names the source ID and
an asserted lineage head. The finding receipt claims that
the exact `retest_pending` snapshot remains current. The schedule receipt
claims that the exact version remains current and not canceled. Changed
authority, source lineage, finding, or schedule state fails closed and requires
a new review path. A supplied schedule also must contain the checked instant
within its original start-inclusive, end-exclusive window, unless it has no
end. The scheduler receipt names an asserted scheduler head.

These receipts are injected assertions, not authenticated evidence by
themselves. This repository does not supply production verifier trust roots,
authenticated producer or tenant binding, an independent current source
inventory, a trusted time service, or a live scheduler. It cannot prove that
a verifier omitted no later conflicting event or that its currentness claim
is true. Even after all receipt fields match, the result explicitly reports
`currentness_proven: false`, `external_trust_established: false`, and
`positive_use_approved: false`. It grants no admission, qualification,
execution, publication, scheduler activation, finding transition, or target
interaction. A production positive-use path must establish those external
trust roots and independently validate fresh authority and lineage at the
moment of use.

`tests/agents/test_offline_change_retest_review.py` covers restartable
history, idempotency, duplicate suppression, independent port binding, stale
authority, finding state, foreign scope, malformed time, no-effect output,
forged packet fields, incomplete or conflicting source lineage, rotated
authority, finding or schedule drift, duplicate verifier identities, and
historical mutation before receipt use.

## Unsigned Conditional Receipt Records

`capture_change_retest_receipt_record` captures the exact native metadata
receipts returned by one conditional revalidation call in a bounded,
content-addressed document. Each port is invoked once. Its returned dict is
copied immediately before another port can mutate a retained reference. The
record contains verifier identifiers, source-lineage and scheduler head
assertions, original packet and history addresses, checked time, and fixed
no-effect flags. It contains no source evidence body or target response.

`verify_change_retest_receipt_record_history` checks the record address,
strict receipt shapes, durable historical candidate, and independently
retained original tenant, event, finding, and schedule. It invokes no external
verifier port and returns only `historical_unsigned_receipt_integrity_only`.
Internally, stored receipt bytes are replayed through the same structural
checks as a live call, but that replay is never described as a fresh check.
A recomputed public hash cannot establish authentic receipt issuance or
original tenant and source provenance.

`revalidate_change_retest_receipt_record_current` checks the old record and
history first, invokes fresh injected ports once each, and requires a checked
instant strictly later than the old one. It issues a new conditional record
linked to the old record digest. Legitimate source-lineage heads may change;
fresh receipt bytes are not required to equal old bytes. A rotated authority,
superseded or conflicting source, changed finding, or canceled schedule
fails closed through the currentness ports. Strict time ordering prevents
byte-for-byte reuse of an old record, but it is not proof of a trusted clock.

Both old and successor records keep `currentness_proven`,
`external_trust_established`, and `positive_use_approved` false. Neither a
verifier ID nor the recomputable record hash authenticates an issuer, proves
complete source inventory, prevents whole-history rollback, or grants live
authority. Production positive use still requires independent trust roots and
fresh use-time checks outside this offline module.

Focused record tests:

```text
python -m unittest tests.agents.test_offline_change_retest_receipt_record -v
```
