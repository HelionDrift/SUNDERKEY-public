# Supplied Pattern Claim Delta

The unsigned pattern delta compares selected hypothesis statuses from exactly
two separately replayed [pattern claim graphs](offline-pattern-claim-graph.md).
Each graph retains its original model, original task and relation sources,
and current catalog binding. The comparison refuses the same set of task
evidence under two graph labels.
Reusing the exact same in-process graph context is rejected before replay.
Different objects still require separate current-source replay and evidence
comparison. Object identity is only a negative shortcut, not proof of
independence.

The caller declares one through sixteen hypothesis pairs and an unverified
subject label for each pair. The output distinguishes
`same_declared_status`, `changed_declared_status`, and `unresolved`.
An unresolved side takes precedence. The verifier rebuilds both graphs and
the comparison from their separate originals rather than trusting the
packet's digest or status strings.
Impossible effect or qualification flags are rejected before that replay;
valid-shaped reports still rebuild both graphs from their originals.

Before and after are caller labels, not established time order. Equal subject
or scope labels do not prove a shared target or identity. A changed status
can reflect changed graph definitions or supplied evidence. The packet does
not claim improvement, regression, a finding, authorization, qualification,
or any operational effect.
