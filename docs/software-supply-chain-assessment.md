# Software supply-chain assessment contracts

`sunderkey.software_supply_chain_assessment` provides deterministic,
repository-only contracts for source code, dependency, CI/CD,
infrastructure-as-code, container image, artifact registry, build provenance,
and software supply-chain assessment.

The capability is nonqualified. It does not prove that an adapter is trusted,
that evidence is complete, or that any operational assessment occurred. It
does not contact a repository, registry, build system, cloud service, or
network. It does not execute a command or mutate a repository.

## Exact assessment binding

`AssessmentContext` binds every plan to one:

* tenant
* execution context
* repository reference
* revision digest
* build reference
* governed scope digest

References are stable identifiers, not values or URLs. Evidence is represented
by an `evidence:` reference plus a SHA-256 content digest. Fields containing
secret, token, password, or credential terminology are rejected at reference
boundaries. No class accepts authentication material or captured secret values.

`build_assessment_plan` also binds a caller-supplied idempotency digest, a
validity window, canonical adapter declarations, and strict budgets. Plans and
all derived artifacts are content-addressed with domain-separated SHA-256
identities.

## Passive adapter boundary

`EvidenceAdapter` is an injected protocol. SUNDERKEY supplies no scanner,
repository client, package-manager client, registry client, command runner, or
network transport. Each adapter receives one exact `AdapterRequest` and must
return a request-bound `AdapterResult`.

Adapter declarations are limited to action tier `R0` and must be passive. A
result must attest that it performed no:

* network call
* command execution
* repository mutation
* registry contact
* secret material return

The contract cannot establish that an external adapter told the truth. Adapter
trust and operational conformance require separate evidence and qualification.

## Evidence families

The import contract supports:

* source manifests
* dependency manifests
* CI/CD configuration evidence
* infrastructure-as-code evidence
* container image manifests
* artifact registry exports
* build provenance
* software bills of materials
* scanner finding exports

`EvidenceRecord` contains only secret-safe references, content digests,
freshness timestamps, graph nodes, and graph edges. Every record is bound to
the exact request. Result bindings include tenant, context, repository,
revision, build, and scope.

`import_evidence` calls each injected adapter exactly once in canonical order.
It rejects undeclared adapters, undeclared evidence kinds, limit overrun,
cross-context substitution, duplicate records, previously seen record digests,
and any effect attestation set to true. The same plan and same evidence produce
the same batch identity. Supplying a previously admitted record digest rejects
replay rather than silently reusing evidence.

## Dependency and provenance graph

Evidence records can describe source, dependency, pipeline, infrastructure,
image, artifact, builder, and provenance nodes. Relationships cover dependency,
builder, production, derivation, publication, and deployment flows.

`analyze_supply_chain` merges identical claims and fails closed when the same
node identity has conflicting attributes. It rejects missing edge endpoints
and enforces plan ceilings for nodes, edges, findings, and proposals.

The deterministic analysis identifies:

* stale evidence
* dependencies without integrity pins
* provenance records without verified integrity
* artifacts or images without admitted provenance relationships
* relationships crossing declared trust boundaries
* publicly exposed build controls

Findings preserve the evidence-record digests that support them. They do not
assert exploitability, reachability, ownership, or operational impact beyond
the imported evidence.

## Candidate remediation and validation plans

Each finding receives one content-addressed `CandidatePlan`. A candidate is
always `proposal_only`, requires separate admission, and specifies a minimum
action tier. Passive freshness collection uses `R0`. Dependency, provenance,
boundary, and exposure validation use `R1`.

Candidate plans never grant network, command, repository mutation, or registry
permissions. A later runtime must perform independent scope, authority,
credential, health, budget, restoration, and evidence admission before any
operational action. This repository increment intentionally does not implement
that runtime.

## Freshness, replay, and tamper controls

The caller supplies all timestamps. The module never reads the wall clock.
Expired evidence remains in the graph and creates a high-priority freshness
finding with a passive refresh proposal.

Canonical array ordering, closed field sets, domain-separated identities, and
constructor validation reject reordered, altered, unknown, or substituted
content. `parse_assessment_report` reconstructs every nested object and checks
all identities. The closed JSON Schema is located at
`registry/schemas/software-supply-chain-assessment-v1.schema.json`.

## Minimal plan example

```python
from sunderkey.software_supply_chain_assessment import (
    AdapterSpec,
    AssessmentContext,
    EvidenceKind,
    build_assessment_plan,
)

assessment_context = AssessmentContext(
    tenant_id="tenant:example",
    context_id="context:authorized-review",
    repository_ref="repository:example",
    revision_sha256="sha256:" + "1" * 64,
    build_ref="build:release-42",
    scope_binding_sha256="sha256:" + "2" * 64,
)
adapter = AdapterSpec(
    adapter_id="adapter:approved-sbom-export",
    adapter_version="v1",
    evidence_source_ref="evidence:approved-sbom",
    evidence_kinds=(EvidenceKind.SBOM,),
    record_limit=500,
)
plan = build_assessment_plan(
    assessment_context,
    (adapter,),
    planned_at="2026-09-20T10:00:00Z",
    valid_until="2026-09-20T11:00:00Z",
    idempotency_key_sha256="sha256:" + "3" * 64,
)
```

The example creates a plan only. It does not load a repository, run a scanner,
resolve dependencies, contact a registry, or authorize target interaction.
