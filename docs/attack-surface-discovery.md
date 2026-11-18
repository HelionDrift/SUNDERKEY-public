# Attack surface discovery and correlation

`sunderkey.attack_surface_discovery` provides repository-only contracts for
joining passive or previously collected evidence across web, API, cloud,
identity, network, code, and third-party exposure surfaces. It resolves assets,
services, and endpoints without implementing an active scanner or a network
transport.

The capability is deterministic and nonqualifying. It does not prove that a
collector is trustworthy, that coverage is complete, that a target exists, or
that any operational discovery occurred.

## Boundary and assurance

Every plan, imported batch, and report declares these effects as `none`:

* active scan
* authority
* cloud access
* credential access
* DNS access
* execution
* network access
* scheduling

`InjectedCollector` is the only collector interface. SUNDERKEY supplies no
implementation that reaches a target. An injected implementation receives one
exact `CollectorRequest` and must return a request-bound `CollectorResult` that
attests that it performed no network call, active scan, or credential-material
return. A false attestation is outside this repository contract and requires a
separately trusted adapter boundary.

Reports declare `evidence_level` as `repository_only`, `operational_status` as
`nonqualified`, and `qualification_effect` as `none`.

## Bounded discovery plans

`build_discovery_plan` binds a plan to:

* one tenant and context
* one governed scope digest
* explicit owner and scope references
* a unique caller-supplied run nonce digest
* an ordered set of passive collector specifications
* a validity window
* per-collector record limits
* global limits for observations, assets, services, endpoints, conflicts,
  gaps, and revalidation proposals

The sum of collector record limits cannot exceed the plan observation limit.
Plans with duplicate collectors, active collector declarations, invalid time
windows, or weakened limits fail closed.

## Observation import

`build_collector_observation` accepts only stable references and SHA-256
digests for native identities, asset identities, services, endpoints, content,
and provenance. It has no field for authentication material or captured secret
values. Each observation is content-addressed and bound to the exact request,
tenant, context, collector, surface family, sequence, timestamps, confidence,
ownership, and scope association.

`execute_discovery_plan` calls each injected collector exactly once in canonical
collector order. The returned result must match the plan, request, tenant,
context, collector, declared surface families, and record limit. Duplicate
observation digests inside a result or batch are rejected. Callers can provide
previously seen observation digests to reject replay across imports. Evidence
from a different request, run nonce, tenant, or context is not admitted.

## Correlation

`correlate_attack_surface` performs three levels of stable resolution:

1. Asset identity uses the admitted asset key digest.
2. Service identity uses the asset relationship and service key digest.
3. Endpoint identity uses the service relationship and endpoint key digest.

The report preserves all observation and provenance digests. Owner and scope
references are associated with each resolved entity. Confidence is conservative
when evidence conflicts. An entity is marked `conflicted` when any supporting
observation participates in a contradiction, `current` when unexpired evidence
exists, or `stale` when all supporting evidence has expired.

Contradictions are retained as content-addressed `DiscoveryConflict` records.
The current rules identify:

* one native key resolving to multiple assets
* one service key resolving to multiple assets
* one endpoint key resolving to multiple services
* disjoint current ownership claims for one asset
* disjoint current scope claims for one asset

The correlator never selects one conflicting claim as truth.

## Freshness and temporal drift

Freshness is evaluated at the caller-supplied report time. The module never
reads the wall clock. Expired evidence remains available for provenance and
creates a high-priority stale-evidence gap.

An optional prior report must have the exact same tenant, context, scope, owner,
and scope-reference bindings. It must precede the new report and cannot point to
the same observation batch. Stable entity IDs produce explicit `added`,
`changed`, `unchanged`, and `missing` links. Missing means not observed in the
new batch. It is not proof that the entity ceased to exist.

## Prioritized gaps and revalidation proposals

The report produces deterministic gaps for missing surface coverage, identity
conflicts, stale evidence, low confidence, missing ownership, missing scope,
missing service correlation, and temporal absence. Priority `1` is highest.
The gap list and corresponding revalidation list are ordered by priority and
content-derived identity.

Each `RevalidationPlan` is a bounded `proposal_only` record. It identifies the
eligible injected collectors and a record ceiling. It always sets active scan
and network access permissions to false. A proposal does not authorize or run
a collector. An operational service must apply a separate authority decision,
admission control, transport boundary, and evidence policy before any target
interaction.

## Closed serialization

`parse_discovery_report` rejects unknown fields, noncanonical arrays, changed
content, or identities that do not match the canonical payload. The JSON schema
at `registry/schemas/attack-surface-discovery-report-v1.schema.json` is closed
and validates the report representation. Content identities use sorted compact
JSON with explicit domain separation.

## Minimal passive example

```python
from sunderkey.attack_surface_discovery import (
    CollectorSpec,
    DiscoveryContext,
    SurfaceKind,
    build_discovery_plan,
)

discovery_context = DiscoveryContext(
    tenant_id="tenant:example",
    context_id="context:authorized-assessment",
    scope_binding_sha256="sha256:" + "1" * 64,
    owner_refs=("owner:security",),
    scope_refs=("scope:assessment",),
)
collector = CollectorSpec(
    collector_id="collector:approved-inventory-export",
    collector_version="v1",
    evidence_source_ref="evidence:inventory-export",
    surface_kinds=(SurfaceKind.CLOUD, SurfaceKind.IDENTITY),
    record_limit=500,
)
plan = build_discovery_plan(
    discovery_context,
    (collector,),
    planned_at="2026-09-20T10:00:00Z",
    valid_until="2026-09-20T11:00:00Z",
    run_nonce_sha256="sha256:" + "2" * 64,
)
```

The example creates a plan only. It does not contact a provider, resolve a
name, inspect a target, or grant permission to do so.
