# Inert email-control review

This repository-only V9.10 slice correlates caller-supplied metadata about
one approved synthetic email scenario. Its approval lists only opaque
`test-mailbox:sha256:` references and closed inert artifact classes:
`header_only`, `inert_link`, and `inert_attachment`. There is no email address,
message body, link URL, attachment content, sender credential, or live mailbox
access in the contract. The system cannot verify that a reference really
belongs to an approved test mailbox. That must be enforced externally.

Each delivery observation binds the approval digest, one test mailbox,
artifact class, asserted gateway disposition, asserted mailbox disposition,
source digest, and short observation window. A cleanup assertion binds the
exact observation digest. Duplicate identical observations are deduplicated;
conflicting outcomes for one mailbox and artifact, cross-scope records,
post-approval observations, orphan cleanup, and future-dated records fail
closed. Approval lasts at most seven days and individual evidence at most two.

A blocked or quarantined gateway outcome paired with an asserted absence from
the test mailbox becomes `asserted_prevention_for_review`. It is not proof of
control effectiveness. Asserted delivery remains `attention_required` even
when cleanup is asserted. Missing cleanup remains an explicit review reason.
Unknown or missing outcomes are inconclusive, and expired evidence is stale.
The asserted-prevention status requires one current observation for every
approved test-mailbox and artifact-class pair. Partial coverage is
inconclusive, even if all observed pairs were blocked or quarantined.
The review is content-addressed and available as `email_control` in the
[offline review workflow](offline-review-workflow.md).

This module never sends mail, accesses a mailbox, collects credentials,
requests user interaction, deploys artifacts, changes a gateway, or contacts
a target. Live validation still needs separately approved test identities,
isolated sending, authenticated gateway and mailbox telemetry, cleanup
receipts, synchronized clocks, independent review, and exact replay. One
asserted outcome cannot establish broad protection against an artifact class.
