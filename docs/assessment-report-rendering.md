# Offline assessment report rendering

`sunderkey.assessment_report_rendering` adds two pure presentation functions:

- `render_assessment_report_html(bundle)` returns a complete static HTML string.
- `render_assessment_report_text(bundle)` returns a plain-text string.

Both require the exact existing `AssessmentReportBundle` class. Before rendering,
the full canonical JSON parser reconstructs the addressed bundle, including all
nested source bindings, counts, partitions, findings, CVSS values, reviewer-role
separation, recorded chronology and freshness, and fixed no-effect maps. The
renderer uses that owned reconstruction, not the caller's records afterwards.
Invalid documents are rejected, not normalized or assigned replacement hashes.
The original bundle, report and component identities and canonical bytes remain
unchanged.

## Shared presentation

Both formats use the same sections and preserve:

- Bundle, report, assessment and executive-summary identities and source hashes.
- Recorded assessment, source-observation, generation and attestation times.
- All coverage metrics, including zero counts and the exact basis-point value.
- All severity and lifecycle counts, including zero counts.
- Negative, abstained, blocked, untested and not-determined outcomes, blocker
  codes, blind spots, scope limits, residual risk and restoration limitations.
- Scoped assets and operations, task outcomes, techniques, profiles, transcript
  hashes, digest-only evidence, validator results and lifecycle references.
- Finding classification, impact, ordered high-level reproduction, remediation,
  validation and retest status, and optional supplied CVSS data.
- Evidence-only attestation partitions and explicitly declared reviewer roles.
- The original bundle's fixed `none` operational effects.

Empty findings, absent validators and empty limitation lists have explicit text.
An empty finding list is not presented as proof that an asset is secure. Complete
coverage is not complete security. Missing optional CVSS values stay missing.

## Static HTML and plain text

Every supplied HTML text value is escaped, including quotes, brackets and
ampersands. URLs remain literal text, never links or resource references. There
are no scripts, forms, active embeds, external styles, fonts or images, nor a
template engine. The page has one main landmark and one top-level heading, ordered
heading levels, captioned tables, and explicit row and column header scopes.

Local neutral semantic color tokens provide normal-text contrast of at least
4.5:1 for the defined foreground/background pairs. Layout uses fluid-width tables
and wrapping for long identifiers and digests. Print CSS keeps headings with
following content and repeats table headers. There are no interactive controls,
so no keyboard focus or loading state is introduced. The content-security policy
denies resource loading and permits only the fixed inline stylesheet.

Plain text has stable section labels, field tables and ordered reproduction
steps. Embedded newlines are indented to remain within their recorded value.
It does not contain terminal control sequences introduced by the renderer. Viewer
wrapping is left to the caller; long content addresses are not modified.

## Local file command

With `PYTHONPATH` set to `src`, render an existing canonical bundle to a new
explicit local file:

```sh
python scripts/render_assessment_report.py \
  --bundle /path/to/existing-canonical-bundle.json \
  --format html \
  --output /path/to/new-report.html
```

Use `--format text` for plain text. The input must be the exact `to_json()`
representation, not reformatted JSON. The local command accepts at most 16 MiB
of UTF-8 input and rejects invalid or noncanonical bundles before output creation.
This command limit does not change the existing report schema or pure functions.

Output creation is exclusive: an existing file, symlink, hardlink or input-path
collision is not overwritten. Parent directories must already exist. A write
failure may leave a partial new output; this is not atomic publication or a
durable custody operation. Review that file before using it. The success summary
explicitly reports the local file creation, while qualification and authority
remain unchanged.

The command does not open a browser, fetch a URL, sign, distribute or upload a
report. The input and output may contain sensitive assessment metadata. Select
an appropriately protected local location; rendering does not encrypt the file,
redact previously accepted fields or establish filesystem access policy.

## Authority and acceptance boundary

These functions return strings only. They do not read or write files, open a
socket, access an API or store, contact a target or provider, use credentials,
sign, distribute, publish, or modify authorization. No current clock or new
freshness claim is introduced. Content-addressed source references and recorded
freshness are verified within the supplied bundle; external source objects,
signature origin and live currentness are not established by rendering.

Declared reviewer identifiers are metadata. Structural separation does not
authenticate those identities, enroll reviewers, or prove independent acceptance.
The compliance claim remains `not_assessed`, and the conclusion remains
`evidence_only_no_compliance_determination`. The view is not a certification,
publication approval, customer acceptance, production readiness or qualification.

This is a bounded P5.6 presentation implementation, not a newly required output
format. Existing canonical JSON and redacted SARIF-like exports remain unchanged.
Production signing, authorized distribution, engineer/security-owner report
acceptance and hosted product operation remain separate requirements.

## Software checks

The focused tests use the existing deterministic Phase 161 report fixtures and
accepted native hostile-looking text, without a target or provider call. They
cover repeat rendering and canonical round trips, preserved identities and
source data, adverse and empty states, optional CVSS, full-bundle mutation/type
rejection, escaping, structural accessibility, static resource exclusion,
declared-role/compliance boundaries, contrast arithmetic and absence of file or
socket access.

These software checks are not a browser rendering certification, screen-reader
audit, PDF/Word rendering result, independent human review or qualification.
Responsive and print rules are checked as deterministic HTML/CSS structure;
visual acceptance in a chosen browser remains separate.
