# Offline Collaboration Review Preview

`offline_collaboration_review_preview.py` derives an internal, metadata-only
preview from a [collaboration review handoff](offline-collaboration-review-handoff.md).
Preparation and verification replay the handoff against the separate original
task and relation inputs, graph model and report, and current specialist catalog.
The handoff address alone is not sufficient to produce or verify a preview.

The preview includes generated graph, handoff, catalog, and preview IDs and
digests; source, claim, and hypothesis counts; counts for each fixed status;
ownership coverage counts; current catalog specialist, commander, and
independent validator profile IDs; and fixed review and effect statuses.
It does not copy caller-supplied graph labels, claim IDs, hypothesis IDs,
source IDs, request bodies, result bodies, explanations, or source content.
The builder constructs an explicit allowlist rather than filtering an
unsanitized record. Exact native JSON bounds and content-addressed comparison
reject added fields, nested substitutions, and type changes. The verified
sources and catalog must remain current for each use.

`review_status` is always `internal_preview_not_reviewed`,
`qualification_effect` is `none`, and `customer_publication_approved` is false.
All operational effects remain `none`. The preview is not an accepted human
review, customer publication, assembled candidate, finding, authorization,
assignment, or qualified safety verdict. It is not a general redaction service:
only this fixed metadata allowlist is constructed, and the original handoff
and source records may still contain sensitive content.
