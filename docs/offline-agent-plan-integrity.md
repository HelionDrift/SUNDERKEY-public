# Supplied agent plan revision integrity

This R0 partial component belongs to specialist `AOE-GD-D20-S19`, capability
`army.gd.d20.s19`, vector `AV-GD-D20-S19-01`, work package
`IWP2-AOE-GD-D20-S19`, and wave `IW2-001`. Its component ID is
`agent_supplied_plan_revision_integrity`. It contributes only partial offline
evidence, not candidate assembly, qualification, routing, or live use.

The exact version 1 model contains labeled evidence sources, one baseline
goal and ordered step IDs, and bounded independent revision proposals. Each
revision declares its previous and proposed goal and step sequence, origin,
approval, application, context completeness, and observation completeness.
These are caller-supplied metadata labels. No prompt, instruction, model
output, plan text, code, command, credential, or target is accepted.

Each proposal is a single-hop comparison to the baseline, not a cumulative
history. If the previous snapshot differs from the baseline, the result is
`unknown`. Unknown origin, approval, application, or incomplete context or
observation also yields `unknown`. A proposal with no goal or ordered-step
change is a declared unchanged plan. A rejected change is not a candidate.
Only a changed proposal from a declared agent or external origin, paired with
declared denied approval and supplied applied outcome, is
`candidate_declared_denied_change_applied`. Owner origin paired with denied
approval and applied outcome remains an unknown conflict. A declared approved
change is unverified and grants no action authority.

`analyze_supplied_agent_plan_integrity` and its bounded JSON-byte variant
produce a deterministic source-retaining report. `from_json` replays its
embedded model but cannot establish that it was the original. Consumers must
call `verify_supplied_agent_plan_integrity(report, model=original_model)`
with the independently held original model. The checked synthetic envelope is
`examples/offline-agent-plan-integrity-component.json`.

The analyzer never calls a model or tool, executes a plan, reads a file, makes
a network or provider request, resolves credentials, interacts with a target,
publishes a finding, qualifies a candidate, or decides authority. Candidate
status is a supplied declaration contradiction, not proof of prompt injection,
plan hijacking, or live behavior.
