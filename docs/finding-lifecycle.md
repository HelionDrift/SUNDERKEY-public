# Finding lifecycle contract

`sunderkey.finding_lifecycle` is a pure, offline contract for durable vulnerability
findings. It does not connect to a target, invoke a tool, generate an exploit,
grant target authority, qualify a component, route work, or deploy anything.
Every emitted object carries an exact `effects` map whose values are `none`.

## Snapshot and event model

A finding snapshot is immutable and content addressed. Its `snapshot_sha256` is
the SHA-256 digest of canonical JSON for every field except `snapshot_id` and
`snapshot_sha256`. The ID is derived from that digest. A successor binds its
immediate parent digest, increments the finding version by exactly one, and
preserves the entire prior event sequence as a prefix.

Events are typed as `created`, `state_transition`, `evidence_added`, or
`retest_recorded`. Each event has its own content digest and binds the previous
event digest. Event sequence and finding version are equal and contiguous.
Every event binds a UTC timestamp, actor ID, authority reference, provenance
digests, and review decision. Evidence is represented only by lowercase
`sha256:` references. Raw evidence, payloads, credentials, and secrets are not
accepted.

The strict state graph is:

```text
new -> triaged -> validated -> accepted -> remediation_in_progress
  |        |          |                          |
  +------> false_positive                       +-> retest_pending
                         accepted -> risk_accepted       |       |
                         remediation_in_progress --------+       |
                                                         |       |
                                              resolved <-+       +-> reopened

resolved, risk_accepted, false_positive -> reopened
reopened -> triaged, remediation_in_progress, retest_pending
```

The code is authoritative where the compact drawing omits an arrow. Illegal
self transitions, skips, rollbacks, reordered history, and broken hash links
fail closed. Evidence-only and inconclusive retest events may retain the state
without claiming a lifecycle transition.

## Finding identity and classification

The dedupe fingerprint contains only normalized, evidence-independent semantics:

1. Asset
2. Surface
3. Vulnerability class
4. Root cause
5. Affected operation or object boundary
6. Semantic claim

Normalization applies Unicode NFKC, trims surrounding whitespace, collapses
internal whitespace, lowercases printable ASCII, and removes a trailing slash
from asset, surface, and boundary values. The literal `unknown` is retained as
an explicit incomplete dimension.

Severity is caller supplied as `unrated`, `informational`, `low`, `medium`,
`high`, or `critical`. CWE references and CVSS vector references are validated
but never inferred. There is no numeric CVSS score field and this module does
not calculate one.

## Deduplication

`compare_findings` returns exactly one advisory outcome:

* `exact_duplicate` with `fingerprint_match`
* `likely_related` with `strong_semantic_overlap`
* `distinct` with an asset, vulnerability class, or operation boundary reason
* `insufficient_evidence` for incomplete semantics or weak signals

The decision includes matched and differing dimensions. Its
`auto_merge_permitted` value is always false. In particular, a likely relation
never merges records. A reviewed `create_merge_record` call is required even
for an exact duplicate.

Merge and supersession records preserve the canonical finding ID, canonical
snapshot digest, every source finding ID, and every source snapshot digest.
They require an approved review decision. Duplicate sources, self references,
and cycles across existing records are rejected.

## Retest contract

A retest plan binds all of the following:

* Finding ID, prior finding version, and prior snapshot digest
* Original validation result and its evidence digests
* Authorized scope reference and technique reference
* Candidate validator versions
* Authorization timestamp, actor, authority reference, provenance, and review

An alternate-technique retest uses `technique_mode="alternate"`. It remains a
separately authorized plan with `status="authorized_plan_only"`. The attempt
API rejects it, so the contract cannot execute or claim execution of an
alternate technique.

An original-technique attempt binds the complete plan, new evidence digests,
and one of `fixed`, `persists`, `regressed`, `inconclusive`, or `abstained`.
`fixed` resolves the finding. `persists` and `regressed` reopen it.
`inconclusive` and `abstained` retain `retest_pending`. Reused evidence,
substituted plan fields, stale finding versions, and results predating plan
authorization fail closed.

## Replay, reports, and verification

`replay_finding_events` reconstructs the current version, state, evidence set,
and last event digest while checking event types, transitions, ordering,
timestamps, and the hash chain. `FindingSnapshot.from_dict` additionally
recomputes every event and snapshot address. Passing `expected_parent` verifies
the direct immutable parent relationship and catches version rollback.

All five addressed record parsers compare exact canonical JSON, not Python
mapping equality. Equal-valued boolean, integer or floating-point substitutions
cannot reuse the original schema, event, snapshot, merge, plan or attempt
identity. Parsing rejects the changed document rather than normalizing it or
issuing a replacement identity. Valid canonical documents retain their hashes.

`build_finding_report` returns a deterministic, content-addressed projection of
the identity, classification, current state, complete event history, related
canonicalization records, and retest attempts. Input order does not affect the
report.

The JSON Schema at
`registry/schemas/finding-lifecycle-snapshot-v1.schema.json` is Draft 2020-12.
Runtime validation remains authoritative for hash identity, normalization,
transition policy, event replay, cycle rejection, and retest binding.
