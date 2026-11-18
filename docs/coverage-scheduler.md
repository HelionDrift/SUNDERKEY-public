# Coverage coordinator and bounded task scheduler

`sunderkey.coverage_scheduler` is a deterministic, offline planning contract. It
turns an already verified assessment scope and an immutable attack world
snapshot into a content-addressed directed acyclic graph of proposed work. It
does not perform the work.

The module has no authority, browser, credential-value, deployment, execution,
network, payload-generation, qualification, request, routing, target-authority,
or tool effects. Schedules and tasks publish all of those fields as `none`.
Request counts are estimates only.

## Inputs

`compute_coverage_schedule` accepts exactly these caller-owned inputs:

1. A `VerifiedAssessmentScope`. Signed but unverified scope documents and plain
   mappings are rejected.
2. An `AttackWorldSnapshot`. The snapshot is round-tripped through its immutable
   identity verifier before planning.
3. A strict capability availability mapping keyed by one of the six task types.
4. A strict validator availability mapping keyed by validator ID.
5. A strict mapping of terminal prior task outcomes.
6. A `SchedulingLimits` value containing the planning time, task, cost, request,
   concurrency, per-asset, snapshot-age, and review-impact bounds.

Extra fields, unknown task types, noncanonical identifiers, secret-like text,
invalid versions, invalid hashes, and unsupported statuses fail closed.

Each capability record has these fields:

```json
{
  "available": true,
  "specialist_profile_id": "profile.passive",
  "commander_id": "commander.one",
  "qualified_scope_ids": ["SAS-0123456789ABCDEF0123456789ABCDEF"],
  "qualified_technique_ids": ["TECH-001"],
  "impact_tier": "R0",
  "estimated_cost_units": 1,
  "estimated_requests": 0,
  "stop_conditions": ["Stop on scope or evidence change."],
  "expected_evidence": ["Digest-bound observation reference."],
  "restoration_required": false
}
```

Capability declarations are availability facts, not qualifications issued by
this module. A capability is eligible only when it is marked available, names
the exact verified scope and technique, and stays at or below the scope impact
ceiling. Missing or unqualified declarations produce blocked reasons.

For technique-specific Army routing, each task type may instead contain a
`default` capability record or `null`, plus a `by_technique` mapping of exact
allowed technique IDs to capability records. An exact technique route wins;
the default is used only when no exact route exists. A missing route is blocked,
not inferred from another technique. Unknown or out-of-scope route IDs fail
closed, and each task type is capped at 512 technique routes. The original
flat task-type mapping remains valid. This permits different specialists and
commanders for different techniques in one schedule without treating a
caller-declared capability as actual qualification or availability.
The task key binds the chosen specialist, commander, validator identities and
versions, impact tier, stop conditions, expected evidence, and restoration
requirement. A successful prior task from a different route cannot silently
satisfy a newly routed task, even when the asset and technique are unchanged.

Each validator record declares `available`, `role`, `version`,
`qualified_task_types`, `qualified_scope_ids`, and `max_impact_tier`. Every task
requires an evidence validator. At or above `review_impact_tier`, a task also
requires distinct Control and Assurance validators. The lexicographically first
eligible validator for each role is selected, which keeps output deterministic.
Validator IDs matching the assigned specialist or commander are ineligible;
if no separate validator remains, that task is blocked. Distinct identifiers
are only a minimum separation check. Real independence and reviewer authority
must be established by separate custody and qualification evidence.

## Frontier and task graph

The coordinator derives an evidence frontier for each in-scope asset and each
allowed technique. It schedules only assets whose node facts contain the exact
verified scope ID. Out-of-scope assets are represented by `scope_mismatch`
blocked records. A technique fact for one asset cannot mark another asset as
covered, suppress its probe proposal, or change its priority.

An edge belongs to its target asset when the target is an in-scope asset.
Otherwise it belongs to its source asset when the source is an in-scope asset.
This makes cross-asset edges target-owned and keeps unrelated service-to-service
facts from proving asset coverage. Only active, exact-scope and exact-technique
edges determine whether that asset has verified, hypothesis, negative, or
missing evidence. Active positive and negative facts for the same claim form
an explicit conflict-review frontier, even when the positive fact is marked
verified. This is a planning heuristic, not proof that an entire technique or
asset has been comprehensively assessed.

The six proposal types are:

1. `context_collection`
2. `passive_analysis`
3. `safe_probe`
4. `validation`
5. `restoration_check`
6. `retest_plan`

For ordinary missing evidence, those tasks form a prerequisite chain. Active
negative evidence suppresses `safe_probe` and `restoration_check` proposals and
adds an `active_negative_evidence` blocker. Hypothesis-only frontiers are lower
priority than missing evidence. Expired hypothesis evidence receives an
additional priority penalty.
Conflicting evidence also suppresses those two proposals, adds an
`active_evidence_conflict` blocker, and preserves context, passive analysis,
validation, and retest proposals for independent review. The conflict on one
asset does not suppress another asset's proposals.

Each proposed task binds:

- the scope content hash and world snapshot hash;
- its asset, node, frontier, and technique IDs;
- its required specialist profile and commander IDs;
- validator IDs, versions, and roles;
- prerequisite and superseded task IDs;
- cost and request estimates;
- impact tier, stop conditions, and expected evidence;
- restoration requirements;
- a semantic task key, content hash, wave, and task ID.

Task IDs are derived from canonical JSON. Schedule IDs are derived from the
complete canonical schedule body. Deserialization recomputes task and schedule
identities, rejects noncanonical ordering, validates prerequisite references,
and checks the graph for cycles.

## Bounded and fair scheduling

Candidate pipelines are sorted by asset, technique, and frontier. Scheduling
then advances one stage across all pipelines before advancing to the next stage.
This provides deterministic round-robin coverage across in-scope assets when a
budget is tight.

The scheduler enforces the supplied maximum tasks, cost units, requests,
concurrency, tasks per asset, and snapshot age. Scope request and concurrency
ceilings are also enforced. It never expands a bound to make work fit. A
constrained item receives a stable blocked reason such as
`schedule_budget_exhausted`, `asset_task_limit_exhausted`,
`capability_unavailable`, or `validator_unavailable`.

Equivalent task keys are unique within a schedule. A successful prior outcome
from the same world snapshot satisfies the equivalent stage and is recorded in
`accepted_prior_outcome_ids`; downstream tasks retain that prior task ID as an
external prerequisite. Failed, blocked, or cancelled outcomes never satisfy a
prerequisite.
An asserted success must include at least one evidence digest. Two successes
claiming the same task key and world snapshot are rejected as ambiguous,
regardless of mapping order. These checks do not authenticate caller-supplied
outcomes; a production consumer must verify their source custody separately.

Waves respect `effective_max_concurrency`, which is the lower of the explicit
limit and the verified scope ceiling. Prerequisite order is preserved across
waves.

## Ready selection

`select_next_ready_task(schedule, completion_state)` is pure. It verifies the
schedule, validates that every supplied task ID is known, honors running-task
concurrency, and returns the first canonically ordered pending task whose
prerequisites succeeded. It returns `None` when no task is ready. It does not
claim, dispatch, route, or execute the returned proposal.

Completion state must be internally consistent. An accepted prior outcome
cannot be reclassified as failed or running, a running or succeeded task must
have succeeded prerequisites, and running task count cannot exceed the
schedule's concurrency bound. Contradictory caller-supplied state fails closed.

## Replanning and lineage

`replan_coverage_schedule` requires a new world snapshot whose parent hash is
the previous schedule's world snapshot hash. The new schedule binds
`parent_schedule_sha256` and `supersedes_schedule_id`. Semantically matching
tasks bind their prior task IDs in `supersedes_task_ids`. The old schedule and
both world snapshots remain unchanged.

This direct-parent rule prevents planning from silently skipping an immutable
world-state transition. Callers that maintain a longer snapshot chain should
replan once per link.

## Published document

`registry/schemas/coverage-schedule-v1.schema.json` is a closed Draft 2020-12
schema for `CoverageSchedule.to_dict()`. Runtime identity validation remains
required in addition to schema validation because JSON Schema does not
recompute content hashes or prove graph acyclicity.
