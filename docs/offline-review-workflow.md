# Offline review workflow

The `offline-review-run` command runs up to 16 same-tenant, same-scope review
jobs from one JSON file and prints one content-addressed bundle to standard
output. It joins eight repository-only reviewers. It does not collect
evidence, contact a target, resolve credentials, publish findings, admit an
action, or qualify an expert.

```powershell
$env:PYTHONPATH = "src"
python -m sunderkey.cli offline-review-run --input review-request.json > review-bundle.json
python -m sunderkey.cli offline-review-verify `
  --input review-request.json --bundle review-bundle.json
```

The input is a UTF-8 JSON object with exactly `schema_version`, `tenant_id`,
`scope_sha256`, `reviewed_at`, and `jobs`. The schema version is `1`.
`scope_sha256` is a lowercase `sha256:` digest and `reviewed_at` is a UTC
timestamp ending in `Z`. Each job has exactly `job_id`, `kind`, and `payload`.
Job IDs must be unique. The command accepts at most 1,000,000 input bytes and
1,000 records per list in a job. Every supplied record must include its exact
fields and a matching content digest. Duplicate JSON keys, unknown fields,
tampered records, and mixed tenant or scope fail the entire request. No partial
bundle is printed.

| Kind | Exact payload fields | Result |
| --- | --- | --- |
| `credential_exposure` | `signals`, `consents` | Human-review triage, never credential use |
| `synthetic_scenario` | `requests`, `consents` | Consent-matched proposal, never delivery |
| `decoy_lifecycle` | `approval`, `events` | Asserted lifecycle and cleanup flags |
| `restricted_asset` | `case`, `observations` | Lower-confidence inference, never exploitation proof |
| `inert_resilience` | `scenario`, `observations` | Inert readiness review, never recovery proof |
| `detection_rule` | `snapshot`, `observations` | Redacted rule hygiene, never detection proof |
| `email_control` | `approval`, `observations`, `cleanup_assertions` | Inert test-mailbox outcome review, never a send or effectiveness proof |
| `metadata_impact` | `observations` | Coarse impact triage, never content access or breach proof |

The record shapes are the respective module `to_dict()` forms documented in
the linked reviewer pages in the product roadmap.
For example, an empty metadata review can be submitted as:

```json
{
  "schema_version": 1,
  "tenant_id": "tenant:example",
  "scope_sha256": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "reviewed_at": "2026-09-23T13:00:00Z",
  "jobs": [
    {
      "job_id": "job:impact",
      "kind": "metadata_impact",
      "payload": {"observations": []}
    }
  ]
}
```

The output sorts jobs by ID and includes each review result and its digest,
plus a digest of the whole bundle. It has no authority or qualification effect.
Verification accepts a bundle up to 4,000,000
bytes, reruns every job from the supplied request, and requires the complete
JSON structure to match, including types and job order. It reports only an
offline reproduction result. It does not authenticate who supplied the input,
verify the asserted source provenance, or make the bundle safe for execution.
An empty or favorable review is not positive authorization. Operators must
obtain provenance, currentness, independent human judgment, and live authority
through separate controls before any target interaction or finding publication.
