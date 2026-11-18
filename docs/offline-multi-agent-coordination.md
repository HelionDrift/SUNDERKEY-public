# Supplied multi-agent coordination trust projection

This R0 partial component serves existing specialist `AOE-GD-D20-S20`,
capability `army.gd.d20.s20`, vector `AV-GD-D20-S20-01`, package
`IWP2-AOE-GD-D20-S20`, and wave `IW2-002`. It adds partial A7.4 offline
evidence only. It does not complete a candidate, qualification,
independent-validation, routing, or live-use gate.

`analyze_multi_agent_coordination(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON source with exactly `schema_version` (`v1`),
`facts_complete`, `approvals_complete`, `agents`, `approvals`, and `messages`.
Agents declare an ID, trust state (`trusted`, `untrusted`, or `unknown`), and
exact privileged action IDs. Approvals declare exact receiver, action, and
participant IDs. Messages declare a sender, receiver, action, optional parent
message, and supplied `accepted`, `rejected`, or `unknown` disposition. Parent
links must preserve the action and connect the prior receiver to the next
sender. Missing parents and cycles are rejected. No natural-language message
content, prompts, tools, credentials, or target identifiers are accepted.

For each message, the projection follows its finite declared parent chain.
Incomplete facts or approvals, unknown participant trust, or unknown message
disposition yields `unknown`. A rejected terminal message yields
`declared_blocked`; a later accepted message claiming a rejected parent is
inconsistent and remains `unknown`.
An accepted chain ending at an agent without the exact privileged action is
`declared_nonprivileged_relay`. An accepted chain ending at a privileged agent
whose own trust state is untrusted remains `unknown`; sender approvals cannot
establish a trusted privileged receiver. An accepted chain ending at a privileged agent
with at least one untrusted participant lacking an exact approval is
`candidate_unapproved_privileged_relay`. An explicit approval for every
untrusted participant or an all-trusted chain is
`declared_approved_or_trusted`. These are classifications of supplied labels,
not authenticated agent identity, message delivery, actual coordination,
execution, or a finding.

The report includes an exact source digest and byte count, per-message relay
and participant IDs, assessment counts, limitations, and no-effect flags.
`MultiAgentCoordinationReport.from_json` validates only local report
structure and address; it does not prove derivation. For trust, use
`verify_multi_agent_coordination(report, *, source_content, source_id)`,
which replays exact original source bytes and compares the full report.

`analyze_supplied_multi_agent_coordination(model)` is the catalog adapter.
Its exact native model has `source_id` and `source`, with `source` matching
`component_fixture()`. The synthetic common-envelope example is
`examples/offline-multi-agent-coordination-component.json`. Its R0 dry run
has empty network, filesystem, process, and credential resources. It sends no
agent message and grants no target, authority, execution, routing,
qualification, or deployment effect.
