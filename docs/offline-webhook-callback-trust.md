# Supplied webhook and callback receiver-policy projection

This R0 partial component serves existing specialist `AOE-GB-D06-S06`,
capability `army.gb.d06.s06`, vector `AV-GB-D06-S06-01`, package
`IWP2-AOE-GB-D06-S06`, and wave `IW2-001`. It adds partial A7.4 offline
evidence only. It does not complete a candidate or any qualification,
independent-validation, or live-use gate.

`analyze_webhook_callback_trust(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON source with exactly `schema_version` (`v1`),
`facts_complete`, `policy_complete`, `receivers`, `prior_acceptances`, and
`deliveries`. A receiver declares its ID, allowed producer IDs, whether a
signature check is required, replay-key mode (`none`, `event_id`, or
`idempotency_key`), and optional maximum event age. Prior acceptances are
declared per receiver with event and optional idempotency-key IDs. A delivery
declares source producer ID, destination receiver ID, event ID, optional
idempotency-key ID, signature-check disposition, optional integer age in
seconds, and supplied receiver outcome. There are no callback URLs, payloads,
headers, signing keys, timestamps, or secrets in the model. Duplicate JSON
keys, unknown fields, duplicate prior IDs or keys per receiver, unsupported
values, and over-bound input are rejected.

Under complete supplied premises, the projection checks exact producer
membership, required signature-check disposition, receiver-scoped replay
context, and age arithmetic. A known rejection condition can resolve to
`reject` even if another field is unknown. Unknown required signature status,
missing required idempotency key, or unknown required age otherwise yields
`unknown`. When the policy is declared complete, a receiver without a policy
is projected as denied by default. An accepted or rejected supplied outcome
opposite the resolved decision is `candidate_policy_contradiction`; an aligned
outcome is `declared_consistent`. An unknown outcome never supports either
claim. A `verified` label is not cryptographic verification, and prior
acceptances are assertions rather than reads from a receiver or database.

The report includes the exact source digest and byte count, each declared
delivery and projection, summary counts, limitations, and no-effect flags.
`WebhookCallbackTrustReport.from_json` validates only local structure and
address. It does not prove source provenance. For trust, use
`verify_webhook_callback_trust(report, *, source_content, source_id)`, which
replays the exact original bytes and compares the full report.

`analyze_supplied_webhook_callback_trust(model)` is the catalog adapter. Its
exact native model contains `source_id` and `source`; `source` matches
`component_fixture()`. The checked synthetic common-envelope example is
`examples/offline-webhook-callback-trust-component.json`. Its R0 dry run has
empty network, filesystem, process, and credential resources. It does not
send an HTTP request, deliver a callback, verify a signature, authenticate a
receiver, or grant target, authority, routing, execution, qualification or
deployment effects.
