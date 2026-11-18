# Supplied Pattern Claim Graph

The offline graph composes premise statuses from two through four separate
[pattern task relations](offline-pattern-task-relations.md). Each source must
provide its own original relation plan, native relation result, original task
model, and native task result. The graph replays every source against current
catalog content before selecting a claim. Two source labels cannot reuse the
same task-result digest to masquerade as independent evidence.
The exact same in-process context object cannot be reused under two source
labels. This definitive duplicate is rejected before replay. Different object
identities do not prove independent evidence, so the normal current-source
replay and task-digest comparison still apply.

The [synthetic graph](../examples/offline-pattern-claim-graph.json) selects a
query premise from one three-job task and a configuration premise from a
different six-job task. Its scope binding is exactly
`caller_declared_unverified`. It can evaluate a bounded conjunction of
matching, contradictory, and unresolved dispositions, with contradiction
taking precedence over uncertainty. Claim selectors must name a single
premise in their declared source. Hypothesis references are closed, scoped,
and acyclic.

A matching conjunction is a reviewer hypothesis only. It cannot prove that
the tasks describe one target, principal, time window, or exploit pathway.
The result is unsigned and keeps source authentication, scope equivalence,
candidate assembly, positive-use approval, and qualification false. Its
operational effects remain `none`. Exporting a result does not replace
separate original and current-source replay.
An exported JSON graph can be verified only by reparsing bounded bytes and
replaying the declared graph against every separate original task, relation,
and current catalog source. Duplicate JSON members and forged flags are
rejected before the exported result is treated as current.
Impossible effect or qualification flags are rejected before the expensive
source replay. A valid-shaped report still requires complete original replay.

The [pattern review handoff](offline-pattern-review-handoff.md) maps the
replayed claims and hypotheses to unaccepted human challenge work, using
current catalog ownership references without promoting any status to a
finding or authorization.

The [pattern claim delta](offline-pattern-claim-delta.md) can compare two
separately replayed graph versions under unverified subject labels. Status
changes are descriptive only and cannot prove target regression or progress.
