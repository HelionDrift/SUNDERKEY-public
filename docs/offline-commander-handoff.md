# Offline commander review handoff

The `offline-review-handoff` command prepares one compact review packet from
an exact [offline review workflow](offline-review-workflow.md) request and its
bundle. It first reproduces every specialist result. A modified bundle fails
closed before any handoff is printed. The packet preserves tenant, scope,
review time, bundle digest, job ID, result digest, and closed reason codes.
It excludes opaque principal, credential, asset, mailbox, and dataset
references from the per-job handoff items.

```powershell
$env:PYTHONPATH = "src"
python -m sunderkey.cli offline-review-handoff `
  --input review-request.json --bundle review-bundle.json > review-handoff.json
python -m sunderkey.cli offline-review-handoff-verify `
  --input review-request.json --bundle review-bundle.json `
  --handoff review-handoff.json
```

Each job enters one of four review lanes:

| Lane | Meaning |
| --- | --- |
| `attention_for_independent_review` | The source reviewer reported a gap, delivery, counterevidence, or another explicit review signal. It is not a severity rank. |
| `candidate_for_independent_review` | The source reviewer produced a bounded proposal or favorable assertion requiring independent assessment. It is not approval. |
| `inconclusive` | Evidence is absent, incomplete, unknown, or not mapped for handoff. |
| `stale` | The source result is expired or stale under its own contract. |

Items remain sorted by job ID, not by urgency. All items require independent
human review. The packet does not choose a reviewer, assign work, reveal
evidence, grant action authority, publish a finding, or contact a target.
The `offline-review-handoff-verify` command reruns the source reviewers and
compares the full packet, including JSON types and ordering. It reports only
offline reproducibility, not origin authentication or source provenance.
Handoff files are limited to 1,000,000 bytes.

This is a repository-only collaboration artifact. A live commander workflow
still needs authenticated reviewer identity, tenant-filtered evidence access,
durable assignment, audit custody, and separately approved action admission.
