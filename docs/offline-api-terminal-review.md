# Offline API Terminal Review

`review_selected_api_terminal_assertion` inspects one caller-pinned latest
finding or remediation record in an existing `SQLiteServiceRepository`. It
first runs the repository's real integrity verification, reads the exact
tenant, context, kind, and resource ID, verifies integrity again, and rereads
the selected record. A changed selected record or database file fails closed.
The database, WAL, and shared-memory files have explicit byte ceilings.

The result is negative-only. Finding statuses `accepted_risk`,
`false_positive`, `remediated`, and `closed`, plus remediation
`closure_status=closed`, return `terminal_assertion_unverified`. A hash,
reference string, or nonempty retest list cannot turn that result into proof.
Other recognized statuses return `no_terminal_assertion_observed`, which is
not an approval or evidence that a later terminal change will be safe.
Unknown statuses and missing records fail closed.

Only the selected latest record is observed. Historical versions, other
resources, and simultaneous cross-read consistency are not established.
The repository verification and selected reads use separate transactions.
An external writer can change state after the final read. The result reports
`cross_read_atomicity` and `live_source_currentness` as `not_proven`.
Authentication of the caller and trust in the supplied repository identity
remain external. No `FindingSnapshot` identity or API status mapping is
inferred.

The auditor does not modify the repository, call an authorizer or admission
port, execute a target action, verify closure, or permit publication. All
authorization, qualification, and target effects are `none`. It cannot block
legacy API callers from asserting a terminal status. Production closure needs
an explicit versioned status contract, exact source binding, fresh current
authority, and authenticated independent review.

Focused tests:

```text
python -m unittest tests.agents.test_offline_api_terminal_review -v
```
