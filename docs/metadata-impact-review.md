# Metadata-only impact review

This repository-only V9.13 slice derives review signals from caller-supplied
category metadata. It does not read dataset contents, field names, rows,
credentials, or query results. A dataset is represented only by an opaque
`dataset:sha256:` reference. Counts are coarse buckets, and the vocabulary for
categories, reachability, and business criticality is closed. Each observation
and review is content-addressed and bound to one tenant and scope digest.

The result can be `review_required` when an active sensitive category and an
asserted verified path coincide, `triage_required` for a hypothesis or a
public-versus-sensitive declaration conflict, `inconclusive` when no sensitive
category is established, or `stale_metadata` when all declarations expired.
Additional reason codes preserve high-criticality and broad-count assertions.
These are triage signals. They are not proof that data was read, exfiltrated,
regulated, or harmed. Caller-declared categories and paths still require
independent provenance and validation.

An observation expires within 30 days of its observation time, and the review
rejects future-dated or older-than-30-day input. The module retains no raw
content and has no data collection, network, execution, authority, or
regulatory-verdict effect. Production use still requires authenticated source
provenance, approved data access where separately authorized, isolated
classification, report redaction, privacy review, durable retention and
deletion controls, and independently verified impact evidence.
