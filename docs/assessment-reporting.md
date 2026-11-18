# Assessment reporting contracts

Phase 161 adds an infrastructure-independent reporting boundary in
`sunderkey.assessment_reporting`. The module only constructs and verifies
immutable values. It performs no network access, integration, target
interaction, execution, exploit generation, qualification, routing,
deployment, or authority change.

## Bundle structure

An `AssessmentReportBundle` contains one `PentestReport` and one
`AssessmentAttestation`. The report contains:

1. `AssetRecord` values for every scoped asset and operation.
2. One `AssessmentRecord` that binds the signed scope hash, attack world
   snapshot hash, schedule hash, task transcript hashes, validator result
   hashes, finding lifecycle snapshot hashes, technique IDs, profile IDs,
   evidence digests, timestamps, source freshness limit, residual risk, scope
   limits, and restoration state.
3. An `ExecutiveSummary` derived from the assessment and findings.
4. Redacted `FindingReport` values.
5. Separate author and technical reviewer roles.

The attestation binds the exact report and assessment hashes. It partitions
coverage into `tested_areas`, `not_tested_areas`, and
`not_determined_areas`. Its fixed `compliance_claim` is `not_assessed`, and its
fixed conclusion is `evidence_only_no_compliance_determination`. It cannot be
used as a compliance certification.

Every major document has a derived uppercase identifier, a SHA-256 content
address, schema version 1, a kind discriminator, and an explicit `effects`
map whose entries are all `none`. Parsing reconstructs the complete object and
compares the canonical result, so digest or content tampering fails closed.
The comparison preserves native JSON types: `true`, `1` and `1.0` are not
interchangeable schema or derived-count values. Nested coverage, basis points
and report records cannot reuse an identity belonging to different canonical
bytes. The public CVSS constructor may still accept an integer score and emit
its canonical floating-point representation; a parser does not normalize
different wire bytes under an existing report identity.

## Coverage and unfavorable outcomes

Each asset operation must have exactly one `TaskTranscript`. Its derived
`asset_id::operation_id` coverage identity must be unambiguous: distinct
asset-operation pairs must produce distinct coverage identities. Individual
identifiers may contain `::` when this uniqueness rule still holds. A task has
one of these mutually exclusive outcomes:

- `tested`
- `negative`
- `abstained`
- `blocked`
- `untested`
- `not_determined`

The assessment derives its counts and basis-point coverage from this exact
partition. Tested, negative, abstained, and not determined outcomes require a
validator result binding. Blocked tasks require a blocker code. Missing or
duplicate operation coverage is rejected.

The executive summary is reconstructed from the assessment rather than
trusted as caller input. It always includes negative task IDs, abstained task
IDs, blocked areas, untested areas, blind spots, scope limits, residual risk,
restoration status, and every severity and lifecycle status count, including
zero counts. A report is `complete` only when there are no abstentions,
blocked areas, untested areas, or not determined areas.

The attestation repeats the tested, not tested, and not determined partition.
Bundle assembly rejects any omission or category overlap. An unresolved
restoration task remains visible in the assessment, executive summary,
attestation, and SARIF-like view.

## Findings and redaction

`FindingReport` requires a title, affected asset and operation, vulnerability
class, CWE reference, severity, confidence, lifecycle status, evidence
digests, impact description, high-level reproduction summary, remediation
guidance, validator result hash, validation status, and retest status.

CVSS is optional. If used, the caller must provide both a complete CVSS v3.0
or v3.1 base vector and its score. The constructor computes the base score only
to check consistency. It never adds a score to output that omitted one. The
declared severity must agree with the supplied score.

Report text rejects common credential, private-key, token, authorization, and
payload patterns. The model has no fields for request bodies, response bodies,
credential values, secrets, or exploit payloads. Evidence is represented only
by SHA-256 digests. Reproduction summaries are limited to twelve short,
non-secret, high-level steps.
The redaction guard also rejects common secret-value phrases and standalone
long `sk-` or AWS temporary-access-key forms. This pattern check is not a
guarantee of complete secret detection; independent review remains required.

## Freshness and source binding

`AssessmentRecord` validates that all assets bind the same signed scope hash.
Every task must bind the same signed scope, world snapshot, and schedule
hashes as the assessment. Validator evidence must be a subset of evidence in
the referenced task. Finding reports must match the assessment's lifecycle
snapshot state and digest, reference a bound validator result, and name a
covered asset operation.

The finding's primary validator must reference the task whose
`coverage_area_id` is exactly the finding's affected asset and operation joined
as `asset_id::operation_id`. Supporting finding evidence may still include
digests from other assessment-bound tasks or assets. This check establishes
the declared primary validation lineage, not independent evidence truth or
publication authority.

The caller supplies `source_observed_at`, `generated_at`, and
`max_source_age_seconds`. Future-dated or older source inputs are rejected.
Task times must remain inside the assessment interval, report generation must
follow the assessment end, and attestation must not precede report generation.
The attestation check applies to direct bundle construction and canonical
parsing, as well as the builder. Equal generation and attestation instants remain
valid. These checks compare declared historical times; they do not establish
trusted timestamp evidence or current publication authority. A standalone
attestation can still be inspected without supplying the report body.

## Separation of duty

The report requires exactly one `report_author` and one
`technical_reviewer`. The attestation requires exactly one
`independent_control`, one `independent_assurance`, and one `attestor`.
Reviewer identities must be unique inside each group, and no report reviewer
may also attest the bundle.

## Deterministic exports

`to_json()` emits canonical ASCII JSON with sorted object keys and no optional
whitespace. `from_json()` accepts only that canonical representation.
`to_sarif_dict()` and `to_sarif_json()` provide a deterministic SARIF-like
view with finding results, content-addressed assets, and invocation properties
that preserve completeness, negative results, abstentions, blocked coverage,
not tested areas, not determined areas, scope limits, and restoration status.
The `export_report_bundle_json()` and `export_report_bundle_sarif()` functions
verify the bundle again before returning the corresponding string view.

The JSON Schema is
`registry/schemas/assessment-report-bundle-v1.schema.json`. It closes every
object with `additionalProperties: false`; Python verification additionally
enforces cross-record hashes, counts, partitions, role separation, CVSS math,
freshness, and content-addressed identity.

## Example assembly

```python
bundle = build_assessment_report_bundle(
    assessment,
    findings,
    report_reviewers=(author, technical_reviewer),
    attestation_reviewers=(control_reviewer, assurance_reviewer, attestor),
    attested_at="2026-09-20T03:22:00Z",
)

canonical_document = bundle.to_json()
sarif_like_document = bundle.to_sarif_json()
```

The builder returns values only. Persisting, signing, distributing, or
displaying those values is the responsibility of a separately authorized
caller.

For inert human-readable views of the same checked bundle, see
[offline assessment report rendering](assessment-report-rendering.md).
The optional local command creates a presentation file, not a signed report,
publication approval, compliance determination or qualification record.
