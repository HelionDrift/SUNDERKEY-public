# Health-state contracts

Roadmap item X1.9 defines deterministic, content-addressed health-state
contracts. The contracts separate evidence supplied by an external collector
from the decision logic that pauses or permits later recovery processing.

The module provides:

- exact tenant, mission, worker, system version, and worker version bindings;
- immutable probe definitions with interval, freshness, failure, and recovery
  thresholds;
- observations with monotonic sequence values, collection time, observation
  time, provenance references, and content digests;
- aggregation across required and optional dependencies;
- explicit healthy, degraded, recovering, unhealthy, and unknown states;
- hysteresis based on consecutive failure and recovery evidence;
- fail-closed handling of missing, stale, future, conflicting, foreign-context,
  and incorrectly bound evidence;
- a contiguous healthy-snapshot requirement before execution recovery can be
  eligible for separate authorization; and
- closed JSON parsing and JSON Schema validation.

## Security boundary

These records do not run health probes, contact a network, read credentials,
write persistence, pause execution, resume execution, or grant authorization.
An eligible recovery admission only means that the supplied evidence passed
the deterministic policy. A separate authorization and an infrastructure
adapter remain mandatory before any runtime effect.

The contracts make no claim about live SUNDERKEY service health. Live health,
probe collection, storage, alerting, orchestration, and runtime enforcement
remain infrastructure-dependent work.

## Aggregation rules

Only the highest sequence observation for a probe is eligible for selection.
Two different observations at that sequence are a conflict. Future evidence
is not selected. Evidence older than the definition's maximum age is stale.
A required dependency with missing, stale, conflicting, future-only, unknown,
recovering, degraded, or unhealthy evidence produces a pause cause.

Failure thresholds prevent a single transient failure from immediately
declaring a dependency unhealthy. Recovery thresholds prevent a single pass
from immediately clearing a prior degraded, unhealthy, or unknown state.
The prior snapshot is content-addressed into the next snapshot so a recovery
admission can require an unbroken sequence of healthy decisions.
