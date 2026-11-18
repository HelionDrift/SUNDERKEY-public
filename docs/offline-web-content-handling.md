# Supplied web content-handling gates

This R0 partial component belongs to existing specialist `AOE-GB-D05-S10`,
capability `army.gb.d05.s10`, and vector `AV-GB-D05-S10-01`. It contributes
partial offline algorithm evidence only, not specialist completion, candidate
assembly, qualification, routing, or live-use approval.

## Finite declared-gate comparison

`analyze_supplied_web_content_handling(model)` accepts exact version 1 data
with source labels, extension-gate rules, media-type-gate rules, and cases.
Tokens are opaque identifiers, not actual extensions, media values, file names,
paths, content, or payloads. Every rule and case references a declared source;
source labels are not authentication or proof of real server behavior. Gate
dispositions are `allow` or `deny` only.

For each case, the analyzer compares the two supplied gate dispositions only
when the case's media token matches the extension rule's expected media token.
A disagreement in that narrow condition becomes
`candidate_declared_gate_differential`. Agreement yields a narrow declared
allow or deny agreement. Any media-extension mismatch is
`unknown_media_extension_mismatch_policy`, even if the two gate decisions
differ, because the decisions may not be semantically comparable. An absent extension or media rule is
`unknown_missing_gate_rule`. Duplicate or conflicting rule identities,
unsupported semantics, missing source labels, and over-budget models are
rejected. No actual upload, parse, storage, or delivery behavior is inferred.

## Replay and effects

The deterministic report retains the supplied model, its SHA-256 address,
source labels, projections, and uncertainty. `WebContentHandlingReport.from_json`
replays the retained model but cannot establish that it was the original
source. Consumers must call
`verify_supplied_web_content_handling(report, model=original_model)` with the
independently held original model. The checked synthetic R0 envelope is
`examples/offline-web-content-handling-component.json`.

The analyzer never reads or writes a file, calls a network endpoint, starts a
process, resolves credentials, generates a payload, publishes a finding,
qualifies a candidate, or exercises target authority. A declared differential
is not evidence of bypass, exploitability, or a live vulnerability.
