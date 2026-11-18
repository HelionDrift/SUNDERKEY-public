# Remediation planning and validation contracts

`sunderkey.remediation_validation_contracts` turns bound finding and attack-path
records into deterministic remediation plans. It is a repository-only,
nonqualifying capability. It does not connect to targets, execute a retest,
change a target, create a ticket, contact an integration, persist a record, or
grant authority.

The matching Draft 2020-12 schema is
`registry/schemas/remediation-validation-contract-v1.schema.json`.

## Bound inputs

`ContextBinding` content-addresses the tenant, assessment, scope, attack world
model, finding snapshot, attack-path set, and evidence bundle. It also supplies
an observation time and an expiry. A remediation plan cannot predate or outlive
that context. Every retest observation, exception, and closure decision carries
the same context and plan identities. Cross-context substitution and rebound
digests fail closed.

The builder reconstructs the typed context and every nested item, control, and
handoff before deriving a plan. Altering a context timestamp without changing
its content address is rejected. `verify_remediation_plan` separately rebuilds
a supplied plan from the exact context, all nested records, and its proposal
metadata. It rejects self-consistent plans that predate or outlive the original
context, or bind a different context address. This check proves only supplied
source consistency. It does not authenticate context producers or establish
current evidence, target authority, or a real mitigation.

`RemediationItem` binds one proposed action to findings, attack paths, evidence,
an owner, dependencies, inherent risk, residual risk, effort, rollback, and
cleanup requirements. Risk reduction is the exact difference between inherent
and residual risk. Priority is the integer ratio of risk reduction to effort,
scaled by one million so ordering does not depend on floating-point behavior.

## Deterministic batches and ownership

`build_remediation_plan` validates a complete dependency graph. It creates one
batch for every ready dependency layer. Within each layer, items are ordered by
descending priority and then by item reference. Cycles and dependencies outside
the plan are rejected.

Every item requires an accepted `OwnershipHandoff`. The accepted destination
must be the item's owner, and the acceptance evidence is hash-bound.
`CompensatingControl` records temporary risk reduction, its evidence, owner, and
expiry. These records represent claims supplied by the caller. They do not
apply a control or communicate with its owner.

## Retest and regression gates

`build_retest_plan` requires regression gates to cover every remediation item.
It carries all rollback and cleanup evidence requirements forward from the
remediation plan. The retest plan remains no-effect. A separate runner may
eventually produce observations, but this module accepts only caller-supplied
`RetestObservation` values.

Each gate observation records pass, fail, inconclusive, or not observed, plus
its evidence digests. A closure recommendation can report
`closed_nonqualified` only when every gate passes, every gate has its required
evidence, and every rollback and cleanup evidence digest is present. This is a
repository-level recommendation, not an operational or qualification decision.

The plan proposer, retest proposer, observation author, and closure reviewer
are separated. A closure reviewer cannot be any of the other three principals.

Closure evaluation reconstructs every supplied typed record and replays the
retest from its exact remediation plan before considering observations. A
self-consistent retest address alone is insufficient. All source items, required
rollback and cleanup digests, context bindings, and plan windows must match the
normal retest builder. A narrowed item set or weakened restoration requirement
cannot produce a closure recommendation.

`verify_retest_plan` checks that complete source replay separately.
`verify_closure_decision` reconstructs a stored recommendation from the exact
remediation plan, retest plan, observation, and optional exception. Both are
pure offline checks. They cannot authenticate evidence producers, prove that a
retest ran, verify a real fix, or establish current live authority.
When the original context is available, use `verify_remediation_plan` before
retest and closure replay to check the complete context-to-plan source join.

## Exceptions and closure

`RiskException` requires separate requester and approver principals. An
exception must expire within 90 days. An exception-based decision also requires
complete item coverage and controls that remain unexpired at review time.
Expired, partial, stale, tampered, or cross-context exceptions are rejected.

`verify_risk_exception` reconstructs the exact supplied plan and exception,
checks their context and plan addresses, restricts item and control references
to the source plan, and requires approval within the plan's declared window.
An exception cannot be approved before its referenced plan exists or after that
plan expires. The source-only check retains the historical contract's inclusive
window endpoints. It does not require full item or effective control coverage;
those remain separate requirements for an exception-based recommendation.
Expired historical exceptions can still pass source consistency without
establishing current risk acceptance, identity, or control effectiveness.

Every supplied exception is checked, including an exception not used by a
fully passing closure recommendation. An unrelated or impossible source cannot
be silently ignored just because the other observations pass. Use the original
context-to-plan verifier as well when that context is available.

The possible closure dispositions are:

* `closed_nonqualified` when all regression, evidence, rollback, and cleanup
  checks pass;
* `exception_active_nonqualified` when an active, independently approved
  exception has complete compensating-control coverage;
* `open` for every other accepted observation state.

## Immutability and idempotency

Top-level records use canonical JSON and domain-separated SHA-256 identities.
Parsing recalculates each identity, so modified content cannot retain an old
identity. Plans, retest plans, and closure decisions include opaque idempotency
keys. `ensure_idempotent` accepts an exact replay and rejects reuse of the same
key for different content.

The replay check accepts only the three exact supported record types. It
reconstructs both the existing record and candidate, rechecks their complete
content addresses and nested contracts, and compares the complete canonical
serialized records. A frozen typed object is not trusted merely because it
still carries the old digest. Mutated existing records, candidates, nested
items, batches, and gates fail before replay is accepted. Unsupported records
and type substitution fail as validation errors, not attribute or iteration
errors. This is immutable source consistency only; it is not source
authentication, currentness, durable key reservation, live admission, or proof
of an executed change.

All top-level effects are fixed to `none` for authorization, integration,
network, persistence, qualification, target execution, and ticketing. This
boundary is enforced in Python and JSON Schema.
