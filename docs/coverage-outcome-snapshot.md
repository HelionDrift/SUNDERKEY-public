# Schedule-bound outcome snapshot

`sunderkey.coverage_outcome_snapshot` derives terminal outcome task keys and
world snapshot hashes from an exact immutable coverage schedule. Callers
provide only a scheduled task ID, terminal status, and bounded evidence digest
list. A claimed success requires evidence. Unknown tasks, pending or running
statuses, duplicate task IDs, changed schedule identity, and serialized task
key substitution fail closed.

The resulting content-addressed snapshot can be converted into the
`prior_task_outcomes` mapping used by the offline coverage scheduler. This
prevents a free-form caller from choosing a different task key or world hash
when the source schedule is available. The snapshot does not authenticate the
status, evidence content, reviewer, or source system. Its effects fix
authorization, execution, qualification, source authentication, and target
action to `none`.
The closed wire shape is `registry/schemas/coverage-outcome-snapshot-v1.schema.json`.
Runtime verification is also required because a schema cannot recompute task
and schedule identities.

For positive publication, admission, consumption, or execution, a separate
durable outcome source and independent review receipt must be verified with
current scope and authority. This module is a structural handoff for local
rehearsals, not a substitute for that source custody.
