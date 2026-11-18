# Offline collaboration review handoff

`offline_collaboration_review_handoff.py` prepares an unsigned human-review
packet from an [offline cross-task claim graph](offline-collaboration-claim-graph.md).
It replays the graph from separate original task and relation inputs and
reconstructs the current specialist catalog before deriving any review item.
Changed originals, source drift, or a substituted graph are refused.

Each selected premise claim receives its current catalog specialist profile,
domain commander profile, and independent validator profile as ownership
references. These profile IDs are not people, assignments, accepted reviews,
or evidence that a commander acted. A selected relation hypothesis without a
single direct component owner remains marked `ownership_incomplete`.
Graph hypotheses list their contributing claims and the union of available
commander and validator references without claiming an independent quorum.

The packet maps supplied statuses to review questions:

| Status | Requested follow-up |
| --- | --- |
| `matches_declared_expectation` | Challenge source, scope, and leaf semantics |
| `contradicts_declared_expectation` | Resolve the declared contradiction |
| `unassessed` | Request missing or ambiguous evidence |

The fixed required reviewer roles are `independent_control` and
`independent_assurance`. `review_status` is always `prepared_not_reviewed`.
`assignment_accepted`, `review_accepted`, `independent_review_accepted`,
`source_authenticated`, `shared_scope_proven`, `full_candidate_assembled`,
`positive_use_approved`, and `qualification_claimed` remain false. All
operational effects remain `none`. Neither a favorable packet nor a matching
graph hypothesis publishes a finding, activates an expert, or grants target
authority.

`prepare_offline_collaboration_review_handoff` returns a bounded,
content-addressed native report. `verify_offline_collaboration_review_handoff`
requires the separate graph report and model, every original source context,
the current catalog, and the repository root. It rebuilds and compares the
complete packet, not only the address. The packet retains identifiers and
digests, not the full source objects. It is not authenticated provenance,
redaction, safe publication, or human review acceptance.

The separate [Offline Collaboration Review Custody](offline-collaboration-review-custody.md)
journal can retain unsigned, per-item operator assertions against a freshly
replayed handoff. Those assertions do not change this packet's unaccepted
review flags or grant any positive-use authority.
