# Offline review transition

The `offline-review-transition` command compares two independently
reproduced [commander review handoffs](offline-commander-handoff.md) for one
tenant and scope. Both source requests, bundles, and handoffs must verify
before a transition is emitted. Review timestamps must be strictly ordered.
Jobs are joined by exact job ID, and output is sorted by that ID.

```powershell
$env:PYTHONPATH = "src"
$sources = @(
  "--prior-input", "prior-request.json",
  "--prior-bundle", "prior-bundle.json",
  "--prior-handoff", "prior-handoff.json",
  "--current-input", "current-request.json",
  "--current-bundle", "current-bundle.json",
  "--current-handoff", "current-handoff.json"
)
python -m sunderkey.cli offline-review-transition @sources > transition.json
python -m sunderkey.cli offline-review-transition-verify @sources `
  --transition transition.json
```

For known reviewer types, the comparison uses the exact content digests of
the source records carried by each reviewer result. This fingerprint omits
the review timestamp, so an unchanged set of declared source records can be
distinguished from a new review at a later time. A second comparison checks
the handoff lane and reason codes. The resulting change types are:

- `added_job`, `removed_job`, or `kind_changed`;
- `same_declared_sources_same_review`;
- `same_declared_sources_review_changed`;
- `changed_declared_sources_same_review`;
- `changed_declared_sources_review_changed`; or
- `unmapped_kind`, which is deliberately inconclusive.

These are comparisons of caller-supplied, content-addressed repository
records. `same_declared_sources` is not proof that a target stayed unchanged.
`review_changed` is not a confirmed regression or verified fix. Every item
sets those two verdict fields to false. No target action, retest, finding
publication, assignment, or authority change occurs. The transition and its
verification report remain offline reproduction artifacts, not authenticated
provenance or live effectiveness evidence. Transition files are limited to
1,000,000 bytes.
