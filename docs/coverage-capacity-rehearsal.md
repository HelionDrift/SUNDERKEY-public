# Offline Army capacity rehearsal

`sunderkey.coverage_capacity_rehearsal` repacks an existing verified coverage
schedule into synthetic waves under explicit specialist, domain-commander, and
validator slot limits. It helps identify contention that the schedule's global
concurrency bound alone cannot show.

The caller supplies exactly one positive capacity for every specialist,
commander, and validator referenced by the schedule. Each limit cannot exceed
the schedule's effective global concurrency. The rehearsal preserves the
schedule's task identities and baseline waves, places every prerequisite in an
earlier wave, and does not exceed global, specialist, commander, or validator
capacity in any wave.
Missing, extra, zero, boolean, or oversized capacity values fail closed.

The result binds the exact schedule ID and digest, all capacity assumptions,
every task assignment, baseline and rehearsal wave counts, and the added wave
count. The content-addressed result is verified by recomputing all assignments
from the bound schedule. Reordered, omitted, or edited assignments fail.

```python
rehearsal = plan_capacity_rehearsal(
    schedule,
    specialist_capacity={"profile.passive": 1},
    commander_capacity={"commander.one": 2},
    validator_capacity={"validator.evidence": 2},
)
verify_capacity_rehearsal(schedule, rehearsal.to_dict())
```

The example capacities must be expanded to cover every profile and validator
in the actual schedule. The output is a planning observation only. One wave is
an abstract unit, not elapsed time. The module neither dispatches agents nor
proves model availability, candidate qualification, throughput, price, or live
readiness.
It has no network, target, authorization, or routing effects. The closed wire
shape is defined by `registry/schemas/coverage-capacity-rehearsal-v1.schema.json`.

`select_next_capacity_ready_task` verifies the schedule, rehearsal, and
caller-supplied completion state before returning a ready task proposal. It
counts running tasks against global, specialist, commander, and validator
limits. A caller-supplied running state that already overcommits any declared
slot is rejected, including when the global concurrency limit is full.
Rehearsal waves provide deterministic priority, not a clock or a
barrier. The selector does not claim, dispatch, or complete work.

## Army catalog binding

`bind_rehearsal_to_army_registry` optionally checks the rehearsal against a
typed and revalidated Army catalog. Every scheduled specialist must be a
current specialist profile, and its commander must be the domain commander
of that specialist's command. Suspended, revoked, and retired profiles are
rejected. The binding records the exact catalog content digest and can be
recomputed with `verify_registry_capacity_binding`. Its closed wire shape is
`registry/schemas/registry-capacity-binding-v1.schema.json`.

Catalog membership is not qualification, availability, or execution authority.
Profiles with `defined` status can be used for a structural rehearsal, but
the result still claims no qualified or deployable Army capacity.
