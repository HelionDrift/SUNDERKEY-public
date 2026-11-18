# Army activation and route-retirement contracts

The Phase 166 Army activation contract package closes the repository-only
design work for roadmap item A7.5 and Phases 159 through 161. It records the
evidence needed to compare an enrolled candidate route with its control route,
review a bounded canary proposal, decide whether an older route is eligible for
retirement, and verify that the prior route can be restored.

The package has no routing or deployment implementation. A record with a
`ready_for_separate_execution` or `ready_for_separate_activation` status is an
evidence conclusion. It is not authority for this library to duplicate traffic,
call a provider, change a deployment, modify a route, or retire a route. Those
effects require a separately implemented execution plane and the authorization
referenced by the record.

## Exact bindings

Every top-level record carries the full `ExactSystemBinding`. It pins the exact
identifier, version, and SHA-256 digest for all nine activation inputs:

1. candidate
2. specialist profile
3. model
4. provider
5. tool
6. prompt
7. policy
8. roadmap baseline
9. qualification result

Every record also carries an `ActivationContext` that pins the tenant, mission,
candidate route, and evaluation cohort by identifier, version, and SHA-256
digest. Inputs cannot be combined across one of these boundaries. Evidence and
reviews repeat the canonical system-binding and context digests so replay into
a different mission or route fails closed.

## Phase 159 shadow routing

`ShadowRoutingObservation` records externally collected control and candidate
result digests, a request fingerprint, a collaboration trace, safety status,
and fresh evidence. It does not generate or duplicate the request. A
`ShadowRoutingReport` aggregates a bounded observation set. Every observation
must have the same exact system binding and activation context. Any unsafe or
nonmatching observation makes the report fail, and a failed report requires
content-addressed failure evidence.

`CollaborationScorecard` measures successful handoffs, ownership conflicts,
and evidence loss. A score at the threshold passes only when ownership
conflicts and evidence loss are both zero. `RouteEquivalenceAssessment` binds
the shadow report and scorecard. It requires approvals from separate
`independent_control` and `independent_assurance` reviewers. Neither reviewer
may be an excluded candidate or operator principal.

## Phase 160 bounded canary

`CanaryActivationPacket` is a proposal for separate execution. It requires:

- an equivalent route assessment
- a distinct evidence reference whose type is
  `bounded_canary_activation_authorization`
- no more than 1,000 traffic basis points, which is 10 percent
- request, token, cost, duration, and error budgets
- at least one critical stop criterion
- a bounded rollback window
- fresh independent Control and Assurance approvals

`CanaryObservation` records measurements supplied by a separate executor. A
budget excess or a triggered stop criterion produces `stopped`. Unknown stop
criterion identifiers fail closed. Non-passing observations require failure
evidence. The contract never starts, stops, or redirects traffic.

## Phase 161 retirement and restoration

`RetirementDecision` can record `retire` only when every bound canary
observation passed and both independent reviewers approved. Any stopped or
unsafe observation results in `retain` and requires failure evidence.

`RollbackContract` is mandatory even when the evidence supports retirement. It
pins a distinct prior route, a `route_rollback_authorization`, the rollback
window, budgets, stop criteria, and both independent reviews. It remains a
contract and performs no route mutation.

`RouteRestorationObservation` verifies evidence supplied after a restoration
attempt. Verification requires the exact prior route and a restoration time in
the half-open rollback interval: at the opening instant is valid, at the
closing instant is too late. A failed observation requires failure evidence.

`ActivationReadiness` binds the complete evidence chain. It can report:

- `ready_for_separate_activation` when equivalence, bounded canary, retirement,
  and rollback-contract prerequisites pass
- `rollback_verified` when a matching restoration observation passed
- `not_ready` with failure evidence for any other state

## Fail-closed rules

All records use canonical printable-ASCII JSON and SHA-256 content addresses.
Parsing rejects unknown fields, unsupported record kinds, changed identities,
and changed content. Evaluation rejects missing evidence, expired evidence,
future evidence, contamination, unsafe evidence, rejected reviews, stale
reviews, same-person Control and Assurance reviews, cross-context records,
budget violations, incomplete failure evidence, and broken record chains.

The strict JSON Schema at
`registry/schemas/army-activation-contract-v1.schema.json` covers all ten
top-level record types. The Python validators enforce semantic conditions that
JSON Schema cannot express, including chronology, exact derivation, content
addresses, reviewer independence, cross-record equality, and decision logic.

## Operational boundary

Every serialized record includes the same `effects` declaration:

```json
{
  "activation": "none",
  "authorization": "none",
  "deployment": "none",
  "model_calls": "none",
  "network": "none",
  "provider_clients": "none",
  "route_retirement": "none",
  "route_restoration": "none",
  "routing": "none",
  "traffic_duplication": "none"
}
```

This contract package makes the remaining infrastructure boundary explicit.
Live shadow delivery, canary execution, provider calls, routing changes,
deployment mutation, route retirement, and rollback execution still require
external infrastructure and independently authorized runtime components.
