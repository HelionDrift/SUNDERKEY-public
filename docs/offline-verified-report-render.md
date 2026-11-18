# Offline Verified Report Render

`scripts/render_verified_assessment_report.py` is an additive local rendering
path for an existing canonical `AssessmentReportBundle`. It requires a second
canonical JSON file containing complete, locally supplied `FindingSnapshot`
histories. The existing renderer and its CLI remain unchanged and do not
perform this origin comparison.

The origin file has this exact shape:

```json
{"histories":[{"finding_id":"FND-example","snapshots":[]}],"kind":"sunderkey.offline-report-finding-origins.v1","schema_version":1}
```

The empty `snapshots` list above illustrates shape only and is rejected. A
real history must contain every canonical snapshot from version one through
the head referenced by the report, in order. History entries must be sorted
by `finding_id`. Serialize without whitespace, with sorted object keys and
ASCII escaping. The origin file is limited to 8 MiB, 200 findings, 4,096
snapshots, and 2,048 embedded event copies. The bundle input is limited to
16 MiB. Duplicate JSON keys, noncanonical bytes, raw unexpected fields,
missing or extra histories, changed snapshot content, and stale heads fail
before an output path is opened.

Example:

```text
python scripts/render_verified_assessment_report.py --bundle bundle.json --origins origins.json --format html --output report.html
```

The command writes only a new explicit local file, never overwriting an
existing path. HTML and text both state `Finding Origins: Matched Local
Originals Only`. The result summary identifies the bundle, report, and
origin-manifest digests and says `origins_matched_local_only`. It makes no
currentness, authenticated review, publication, authority, qualification, or
target-effect claim. A self-consistent forged bundle and forged origin file
cannot be distinguished from genuine producer custody by local hashes alone.
The caller must separately establish trusted origin, currentness, and
authorization before any positive publication or action.

Focused tests:

```text
python -m unittest tests.agents.test_offline_verified_report_render -v
```
