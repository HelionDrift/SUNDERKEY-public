# Offline reference analysis integrity

This is a bounded repair of the existing six-adapter D016 reference slice.
It analyzes supplied synthetic metadata only. It does not qualify a candidate,
authenticate source observations, evaluate a live permission system, or grant
target, routing, deployment, credential, or containment authority.

## Identity and endpoint witnesses

Identity analysis requires native lists for `start_principals` and
`privileged_entitlements`. Endpoint analysis requires a native string
`start_context` and a native list `privileged_contexts`. Every declared
principal or context is native, nonempty ASCII text. A bare string cannot be
interpreted as an array of individual characters. Invalid declared input
produces the existing failed-closed abstention, not a negative finding.

The shared graph search runs a separate breadth-first traversal for each
distinct start, ordered by start name. Neighbors are visited in sorted order.
Each reachable start/goal pair has one shortest witness, including a
zero-edge witness when the start is itself a declared goal. Reaching one
privileged goal does not stop traversal toward another. Visited nodes are
local to each start, so a shared entitlement does not erase another
principal's witness. Cycles, duplicate edges, and alternative paths do not
produce an enumeration of all simple paths.

These are paths through caller-supplied edges, not proof that any edge is
effective in a directory, operating system, tenant, or target. Existing
finding names and result domains are unchanged. Previously omitted reachable
pairs intentionally add observations and change the addressed result.

## Cloud literal indicators

Every statement's `effect` must be a native string in the existing `Allow` or
`Deny` vocabulary. Native type validation precedes vocabulary membership, so
malformed containers and string subclasses produce an abstention rather than
a raw membership error or an accepted statement.

Every statement's `actions` and `resources` must be native lists whose every
element is native, nonempty ASCII text. All elements are validated before
classification, even when an earlier element is `*`. Invalid elements produce
an abstention instead of a malformed-input negative result or finding.

The existing rule remains a literal indicator: an `Allow` statement containing
the exact string `*` in both arrays yields `unbounded_cloud_iam_allow`.
Other valid statements retain `bounded_cloud_iam_statement`. The latter name
does not establish effective IAM safety. This repair does not implement
service-pattern expansion, conditions, deny precedence, provider policy
evaluation, or live access checks.

## Passive fingerprint provenance

For each fingerprint, passive analysis retains the first supplied asset ID
and source ID. A later observation of a different asset with that fingerprint
cites the original source ID and the current source ID in sorted, unique
order. Repeating the original asset does not replace its initial provenance.
Asset IDs remain sorted in each duplicate observation. Distinct fingerprints
retain the existing negative inventory summary.

Source IDs are declared provenance labels, not independent authenticity or
proof that fingerprints identify the same real asset. Adding the missing
supporting label intentionally changes affected result and evidence hashes.

## Regression and integration boundary

`tests/agents/test_reference_adapter_analysis_integrity.py` exercises actual
public reference adapters using the approved D016 and blueprint inputs and a
fresh, in-memory catalog bound to the source under test. It covers nested
goals, shared goals, deterministic shortest witnesses, cycles, native array
and element rejection, literal IAM controls, provenance retention, negative
controls, and unchanged input metadata.

The checked adapter catalog and development-gate catalog must be rebuilt from
the new source bytes before their current-source checks can pass. Their
reference-only statuses and real containment blockers must remain intact.
Existing signed approvals and historical execution evidence are not rewritten
to describe the repaired source. This guide does not claim that catalog
rebinding, software regression success, or synthetic findings establish live
runtime evidence, qualification, parity, or production readiness.
