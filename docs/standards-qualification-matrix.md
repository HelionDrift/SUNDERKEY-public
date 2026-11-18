# Standards qualification matrix

The standards qualification matrix is an offline, content-addressed coverage artifact. It connects SUNDERKEY technique identifiers and specialist profiles to exact standards releases and to the evidence contracts required for later qualification work. It does not qualify a specialist, authorize an action, route a task, contact a target, or execute a technique.

## Purpose

The matrix answers four repository questions:

1. Which exact standards releases were reviewed?
2. Which controls were explicitly mapped to each technique and specialist profile?
3. Which qualification requirements are complete, partial, or absent?
4. Which release pins or mappings need review?

It does not answer those questions by inference. Missing information is emitted as a gap.

## Standards coverage domains

`RECOMMENDED_STANDARD_IDS` identifies the intended coverage families without selecting a release:

- MITRE ATT&CK Enterprise, Mobile, and ICS
- OWASP ASVS, API Security Top 10, Top 10, and Web Security Testing Guide
- CWE and CAPEC
- NIST SP 800-115 and the assessment controls from NIST SP 800-53
- PTES and OSSTMM
- CREST penetration testing guidance
- PCI DSS testing requirements
- IEC 62443
- AWS, Azure, and Google Cloud security guidance

The list is a coverage target, not a set of pins. A caller must provide each exact release identifier, publication date, review date, and artifact SHA-256. Floating labels such as `latest`, `current`, or `rolling` are rejected. The module has no fetching or network path.

## Release pins

`StandardReleasePin` binds:

- a stable standard family identifier;
- an exact release identifier;
- its publication date;
- the date the release was reviewed for matrix use; and
- the SHA-256 of the reviewed source artifact.

The pin identifier and pin hash are derived from canonical JSON. Changing any field changes the content address. A review date before publication is invalid. A publication or review date after the matrix `as_of_date` is invalid.

The matrix reports a required pin as stale when its review age exceeds `max_review_age_days`. It preserves the original pin and records `stale_release_review`; it does not silently refresh the date or select a newer release.

## Technique mappings

`TechniqueQualificationMapping` binds one technique and one or more specialist profiles to these dimensions:

- exact controls in pinned standards;
- prerequisite identifiers;
- safe proof identifiers;
- negative control identifiers;
- restoration identifiers;
- evidence requirement identifiers;
- validator identifiers; and
- qualification scenario contracts.

Values are inert identifiers. The matrix does not store exploit payloads or executable instructions.

Every scenario must reference declared prerequisites, safe proofs, negative controls, restoration checks, evidence requirements, and validators. An incomplete scenario is rejected. A `complete` mapping must populate all dimensions. A `partial` mapping must list exactly the dimensions that remain absent. A `gap` mapping must contain no mapping content, which prevents an unknown control relationship from being presented as established.

Standard control references must resolve to a pin in the same matrix. Missing referenced pins fail closed. Duplicate standard pins, duplicate control groups, duplicate scenarios, and duplicate technique plus specialist bindings are rejected.

## Expected coverage and gaps

The builder accepts explicit expected standard, technique, and specialist profile identifiers. It emits deterministic gaps for:

- a missing release pin;
- a stale release review;
- a missing technique mapping;
- an explicitly incomplete technique mapping; and
- a specialist profile that has no mapping.

Gap entries contain only the subject, reason code, and missing dimensions. They do not fabricate a control, validator, scenario, or remediation.

Coverage metrics use integer counts and integer basis points. A technique counts as complete only when at least one explicit mapping for that technique is complete. Partial coverage is not promoted to complete. With no expected techniques, coverage is zero basis points rather than an implied success.

## Integrity and limits

Pins, technique mappings, and the matrix release are independently content addressed from canonical JSON. `from_dict` and `from_json` rebuild the artifact and compare every derived value, including gaps and metrics. Tampering therefore fails closed.

Hard limits cover pin count, mapping count, list sizes, scenario count, review age, and serialized bytes. `MatrixLimits` may reduce these ceilings but cannot raise them.

The JSON Schema at `registry/schemas/standards-qualification-matrix-v1.schema.json` describes the serialized artifact. The Python constructor remains authoritative for cross-field rules such as content hashes, exact missing dimensions, date ordering, pin resolution, and scenario subset checks.

## Effects

Every matrix declares these effects as `none`:

- authority;
- execution;
- network;
- qualification; and
- routing.

Promotion from matrix coverage into an approved qualification plan remains a separate governed process.

## Minimal construction flow

1. Obtain a standard artifact through an approved process outside this module.
2. Record its exact release identifier, publication date, review date, and SHA-256 in a `StandardReleasePin`.
3. Create explicit control references and inert qualification requirements.
4. Create complete, partial, or gap technique mappings.
5. Call `build_standards_qualification_matrix` with explicit expected coverage identifiers and an `as_of_date`.
6. Validate the serialized result against the schema and preserve its matrix hash with the release record.

Rebuilding with the same inputs produces the same canonical document, identifier, gaps, metrics, and content hash.
