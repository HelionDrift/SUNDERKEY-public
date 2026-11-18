# Deterministic Attack Coverage Matrix

The attack coverage matrix is a repository-only classification boundary. It
maps governed attack technique references to specialist capability references,
asset types, evidence grades, prerequisites, negative-space gaps, and blocked
reasons. Every reference, row, and matrix document is content addressed.

The matrix is not an execution engine. It does not inspect a target, access a
credential, call a network service, deploy infrastructure, authorize an
action, or qualify a specialist. It makes no claim of live validation,
production readiness, or competitive parity.

## Coverage domains

The default baseline contains one explicit row for each of these domains:

* Web
* API
* Identity
* Cloud
* Containers
* Kubernetes
* CI/CD
* Source and dependency supply chain
* Mobile
* Desktop and thick client
* Network
* Wireless
* Hardware and firmware
* OT/ICS
* AI/ML
* Blockchain
* Social engineering
* Physical
* Cryptographic and PKI
* Multi-stage chaining

The baseline is deliberately conservative. Its specialist bindings use the
`catalog_only` evidence grade. Every row preserves at least one explicit gap.
Rows that require a radio environment, representative hardware, an industrial
test range, or a policy decision are blocked. Other rows are partial. Nothing
in the baseline represents live observation.

## Input contracts

A technique reference contains a tenant, assessment context, scope digest,
fixed catalog and technique versions, attack domain, and one or more asset
types. A specialist capability reference contains the same boundary values,
fixed specialist and capability versions, supported domains, an evidence
grade, and an optional evidence digest.

Moving versions such as `latest`, `main`, and `rolling` are rejected. The
supported evidence grades are intentionally bounded to:

* `none`
* `catalog_only`
* `repository_contract`
* `offline_deterministic`

There is no live or production evidence grade. A caller cannot use this module
to encode a live-validation claim.

A coverage mapping joins one technique reference to zero or more specialist
references. It also records prerequisites, negative-space gaps, and blocked
reason codes. Every technique must be mapped exactly once. Every supplied
specialist reference must be used.

## Status invariants

The matrix uses four statuses:

| Status | Required properties |
| --- | --- |
| `repository_covered` | One or more specialists, repository or offline evidence, no gap, no blocked reason |
| `partial` | One or more specialists and at least one negative-space gap |
| `gap` | No specialist, at least one gap, and a missing capability or evidence reason |
| `blocked` | At least one gap and at least one blocked reason |

The `repository_covered` status describes only repository evidence. It does
not mean live coverage, operational readiness, or authorization.

## Boundary isolation

All technique and specialist references in a matrix must have the same tenant,
context, and scope digest. Cross-tenant, cross-context, and cross-scope joins
are rejected. Specialist references must declare the domain of every technique
to which they are mapped.

Duplicate technique references, specialist references, mapping keys,
technique mappings, asset types, domains, prerequisites, gaps, and blocked
reasons are rejected. Unknown enum values, malformed digests, stale content
addresses, extra serialized fields, and noncanonical JSON are also rejected.

Secret-like strings and strings that resemble executable payloads are refused
before serialization. This keeps the matrix appropriate for control-plane
metadata and prevents it from becoming a payload transport.

## Deterministic output

Inputs are normalized and sorted before rows are assembled. The canonical
document uses printable ASCII JSON, sorted keys, compact separators, and no
non-finite numbers. Reordering equivalent input sequences therefore produces
the same bytes and the same SHA-256 identities.

Each row publishes:

* The governed technique reference
* Its specialist capability references
* Domain and asset types
* The weakest evidence grade across mapped specialists
* Coverage status
* Prerequisite references
* Negative-space gaps
* Blocked reasons
* Row identity and digest

The summary contains row, technique, specialist, asset-type, and gap counts,
plus deterministic counts by domain, status, evidence grade, and blocked
reason. These are inventory metrics, not effectiveness or readiness scores.

## Safe integration sequence

1. Bind an exact tenant, context, and scope digest.
2. Load fixed-version governed technique references.
3. Load fixed-version specialist capability references and evidence digests.
4. Create one mapping for every technique.
5. Build and persist the canonical matrix document.
6. Verify the document before using its rows as planning input.
7. Keep authorization, live execution, qualification, and readiness decisions
   in their dedicated control planes.

The JSON Schema in
`registry/schemas/attack-coverage-matrix-v1.schema.json` validates the wire
shape. The Python parser additionally recomputes derived fields, validates
content addresses, and enforces semantic invariants that JSON Schema alone
cannot express.
