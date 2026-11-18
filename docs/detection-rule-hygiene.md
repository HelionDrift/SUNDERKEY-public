# Detection-rule hygiene review

This repository-only V9.10 slice reviews caller-supplied, redacted detection
rule metadata. A snapshot identifies one opaque rule, its enabled state,
asserted query health, asserted mapping currency, and opaque required source
references. Separate source observations assert availability, absence, or an
unknown state. No rule query, source data, alert content, or SIEM credential
enters the contract.

Disabled rules, asserted query errors, stale mappings, and asserted missing
sources require attention. Missing or unknown observations remain inconclusive.
Expired snapshots and source observations are stale. Even when all metadata
is asserted healthy, the result is only `metadata_healthy_for_review`, not
proof that the rule detects an attack. Conflicting source evidence and
cross-tenant, cross-scope, or unlisted source evidence fail closed.

The module performs no connector read, telemetry collection, query execution,
rule change, network call, or authorization. Source and snapshot digests are
caller-supplied assertions, not authenticated vendor evidence. A future
proposal to tune a rule would still need independent review, change approval,
rollback planning, and exact replay against representative telemetry.

Production completion requires authenticated read-only rule inventory,
current source health, query-performance evidence, mapping provenance,
representative telemetry, verified detection outcomes, and controlled change
and rollback workflows. Metadata hygiene alone cannot establish control
effectiveness.
