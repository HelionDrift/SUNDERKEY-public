# Offline Mission Action Custody

`capture_offline_mission_action_custody` reads one mission's authenticated
action admission and execution history from MissionStore and returns a
content-addressed, redacted version 3 status snapshot. It does not invoke an adapter,
replay an action, contact a target, access credentials, or grant authority.

## Historical Verification

Capture opens one MissionStore read transaction with SQLite `query_only`,
checks database integrity and the current schema, and runs the existing
whole-store historical verifier with live-currentness disabled. That verifier
includes action authority, admission, execution, replay, budget, and terminal
custody. Only then does capture read the requested mission and join up to 100
of its admission receipts with revocation, consumption, execution request,
and terminal rows. Capture requires an explicit `expected_tenant_id`, filters
to that tenant, and fails if the mission has any admission receipt assigned
to another tenant. It also fails if there are no admission receipts, because
MissionRequest does not provide a tenant binding for an empty action history.
Unknown missions, empty-history missions, and cross-tenant histories return
the same unavailable-for-tenant error to avoid a simple mission-existence
oracle. This does not make timing or the wider service an authorization gate.
A larger mission history fails closed rather than emitting
an incomplete view. The verification pass itself can examine more than 100
records because Phase 196 has global replay and budget chains.

## Review-to-Action Lineage

For each admission, the same read transaction resolves its typed action
resolution to the exact tenant- and mission-bound proposal import. The snapshot
exposes only the proposal import and product identities and digests, the review
snapshot and closure identities and digests, and the review evidence digest
sealed at admission. It also checks for a later durable revocation of that
closure and reports its identity, digest, and `recorded` or `not_recorded`
status. The historical verifier already checks the full admission, proposal,
review, and execution chains before projection; capture additionally compares
the normalized proposal and revocation joins against the exact resolution.

The snapshot also exposes the historical origin workspace ID and digest, plan
ID, and reviewed work ID. These come from the authenticated proposal import,
the admission-time review snapshot, and the typed action resolution. Capture
checks their exact tenant, mission, plan, work, and product bindings inside the
same read transaction. The historical workspace digest describes the state
reviewed before admission. It is not a claim about the workspace's present
state or a current execution authorization.

`not_recorded` means no closure revocation was present in this read
transaction. It does not establish current approval, and a revocation can be
recorded later. The admission review evidence digest remains unchanged after
later revocation, so the two facts are reported separately. This projection
reports MissionStore revocation custody, not a separately verified workspace
revocation projection. It does not include reviewer identities, assertion data,
work-product contents,
proposal parameters, or raw review documents.

The projection distinguishes an unconsumed admission, a revoked unconsumed
admission, an execution request with no terminal, and the four terminal states.
`terminal_missing_reconciliation_required` is conservative. It does not say
whether a worker is still active or whether an external invocation happened.
Never redispatch solely because a terminal is missing. A terminal exposes
separate action outcome, evidence, cleanup, and restoration status axes.

## Redaction and Trust Boundary

Output binds the expected tenant and contains only mission revision and head
digest, review and action lineage identities and digests, revocation identities,
terminal status, and coarse
outcome axes. It does not export action parameters, adapter input, result
documents, evidence bodies, assertions, authorizations, credential references,
or principal identities. The content hash detects changes to the snapshot
document; it does not authenticate its producer or anchor the SQLite file
against replacement by someone who can rewrite the entire store.
The expected tenant is a caller assertion, not authenticated by this module.
The service has no tenant authentication or permission gate. Its caller must
authenticate and authorize the exact `(tenant_id, mission_id)` pair before
showing this sensitive status metadata to anyone. A matching nonempty receipt
does not replace that external authorization.

`OfflineMissionActionCustodySnapshot.from_dict` and `.from_json` check only
document structure, internal consistency, canonical bytes, and a publicly
recomputable hash. A fabricated document with a recomputed hash can pass
parsing. `verify_offline_mission_action_custody_snapshot` separately reruns
capture against the supplied MissionStore with the same expected tenant and
requires exact document equality. Parsing refuses documents larger than
262,144 bytes before invoking JSON decoding. Excessive nesting is also
reported as a validation error rather than leaking a parser recursion error.
It rejects a forged projection or one made stale by later store history. This
is a fresh historical comparison, not producer authentication, cross-store
atomicity, or an assertion that the store remains unchanged after the check.

This is historical integrity, not live source currentness. The snapshot
cannot authorize publication, admission, consumption, replay for use,
execution, a finding, or a retest. Every positive use must independently
check fresh current sources, trust, scope, review, health, and action policy.

Focused tests:

```text
python -m unittest tests.agents.test_offline_mission_action_custody -v
```
