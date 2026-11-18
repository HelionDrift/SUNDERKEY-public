# Impact Demonstration Policy

## Purpose

The Phase 172 impact demonstration policy converts injected, opaque evidence
references into deterministic plans and planning receipts. It provides a safe
way to decide what an impact demonstration would need to prove without
performing the demonstration.

The module is effect-free. It does not authorize an action, contact a target,
open an artifact, use a credential, execute a payload, change a role, pivot a
session, modify data, reduce availability, or verify cleanup. A plan with
status `evidence_plan_only` is not execution authority.

## Modes

| Mode | Evidence categories that can be planned | Required review |
| --- | --- | --- |
| Off | None. Submitted intents are suppressed. | None |
| Moderate | Captured credential and role change | Current, exact operator approval |
| Deep | Captured credential, role change, lateral pivot, and data modification | Current, exact operator approval plus an independent reviewer |

Availability impact and destructive proof are always prohibited. Deep mode
does not relax these prohibitions.

## Exact binding

Every request binds all of the following values:

- tenant reference
- assessment context reference
- scope reference and scope digest
- target reference and target digest
- session reference and session digest
- policy reference and policy digest
- protected target flag
- production data flag

Approvals and reviews carry the digest of this complete binding. They also
carry the exact mode and exact set of proof categories. A missing, expired,
cross-context, or category-mismatched record fails closed. Deep review must be
performed by a different principal from the operator.

Protected targets and targets that contain production data cannot receive a
Moderate or Deep plan. Off mode remains available to record that no impact
demonstration is planned.

## Evidence-only intents

An intent can contain only opaque references and SHA-256 digests for:

- existing evidence
- reversible proof
- cleanup plan

It cannot contain a credential, secret value, command, payload, target URL, or
artifact body. Supported artifact classes are aggregate metrics, metadata
snapshots, redacted transcripts, and state deltas.

Each planned category has a fixed cleanup verification obligation:

| Category | Cleanup verification obligation |
| --- | --- |
| Captured credential | Credential invalidation verified |
| Role change | Role restoration verified |
| Lateral pivot | Pivot session termination verified |
| Data modification | Data restoration verified |
| Availability impact | Availability restoration verified, but planning is prohibited |
| Destructive proof | Destructive recovery verified, but planning is prohibited |

The policy does not claim that cleanup occurred. It records the evidence that
a later, separately governed workflow would have to produce.

## Artifact minimization

Moderate mode has a total metadata ceiling of 4,096 bytes. Deep mode has a
total metadata ceiling of 16,384 bytes. Off and denied plans retain zero
artifact bytes. Every step fixes both `persist_raw_content` and
`persist_secret_material` to `false`. The only permitted proof method is an
existing evidence reference.

## Content addressing and parsing

Plans use the `IDP` identity prefix. Planning receipts use the `IDR` prefix.
Both identities derive from canonical printable ASCII JSON, a domain
separator, and SHA-256. Strict parsers reject unknown fields, malformed
references, invalid timestamps, noncanonical JSON strings, semantic
inconsistency, effect escalation, and content-address drift.

The plan schema is
`registry/schemas/impact-demonstration-plan-v1.schema.json` and uses JSON
Schema Draft 2020-12.

## Integration boundary

All inputs are supplied by the caller. The policy performs no file discovery,
network access, environment-variable access, clock access, secret lookup, or
runtime dispatch. The caller must inject an aware evaluation timestamp. Any
future runtime integration must separately enforce scope, authority, target
health, stop readiness, restoration readiness, and evidence custody. Nothing
in this module grants those capabilities.
