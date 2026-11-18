# Offline remediation workflow visibility

`review_remediation_workflow` joins an exact remediation plan with asserted
service targets and delivery observations. It reports missing targets, overdue
dates, failed or pending delivery, stale observations, conflicting ticket
metadata, and stale plan sources for every item. It does not assign work,
enforce a deadline, create or close a ticket, notify an owner, schedule a retest,
accept a risk exception, or declare a fix.

The plan's existing accepted ownership handoffs remain the accountable-owner
source. A target or observation must name an item and its exact owner from that
plan. The reviewer reconstructs the source plan and each typed input, rejects
old-address mutation, duplicate target assignments, duplicate observation
identities, unknown items, and source timestamps outside the plan-to-review
window. It accepts at most 2,048 targets and 4,096 observations.

## Deadlines and delivery

`RemediationServiceTarget` records an opaque item, accountable owner, policy
digest, recording time, and due time. The due time must follow its recording
time. The due instant is overdue inclusively. A service target may extend
beyond the source plan's evidence window, but an expired plan is always
explicitly flagged. Neither the policy digest nor the owner's reference is
authenticated by this module.

`RemediationDeliveryObservation` contains opaque observer and ticket references,
a source digest, a timestamp, and separate asserted delivery and ticket states.
No URL, ticket body, secret, or network client is accepted. A reported delivered
ticket or known ticket state requires a ticket reference. Missing evidence is
unknown, not success. Observations older than the chosen age limit are stale;
the exact freshness boundary is retained. The default is 24 hours and the
maximum is seven days.

Equal-time disagreements remain conflicts. Distinct fresh ticket references
for one item remain ambiguous because the reviewer has no authenticated ticket
supersession relation. All observation digests, including stale ones, remain
in the result for review. A reported closed ticket adds an explicit warning
that ticket closure is not remediation evidence. It cannot suppress an overdue
target or set a resolved state.

## Replay and limits

The view binds the exact source plan, full target set, full observation set,
review time, and freshness limit. Input order does not affect the digest.
The closed output schema is
`registry/schemas/remediation-workflow-review-v1.schema.json`. It enforces
the bounded shape, false claims, and no-effect fields. Source replay, valid
calendar times, ownership joins, and content addresses remain runtime checks.
`verify_remediation_workflow_review` rebuilds the entire advisory view from
those sources and rejects missing records, substituted plans, changed values,
and Boolean-to-integer type substitutions.

Every item remains `remediation_state="unverified"` and requires review. All
delivery, owner, deadline-enforcement, and remediation claims remain false.
All effects are `none`. Independent retest and closure source replay remain
separate in `remediation_validation_contracts`; this view never substitutes
ticket status for those checks.
The view binds the plan's context digest but does not receive the original
context. Callers with that source must separately use `verify_remediation_plan`
to check the complete context-to-plan join. Content hashes do not authenticate
the context, owner, or delivery observer.

This is one repository-only portion of V9.16. Authenticated ITSM provenance,
secure assignment custody, exception renewal, approved change delivery,
durable scheduling, qualified revalidation, independent closure decisions,
and production operations remain separate work. No live integration or
qualification is implied by this view.
