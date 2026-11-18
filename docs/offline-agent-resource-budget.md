# Supplied Agent Resource Budget

This R0 partial component belongs to specialist `AOE-GD-D20-S18`, capability
`army.gd.d20.s18`, vector `AV-GD-D20-S18-01`, work package
`IWP2-AOE-GD-D20-S18`, and wave `IW2-020`. Its commander is
`AOE-GD-D20-CMD`, and its independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The bounded version 1 model contains caller-supplied request, token, and
micro-USD ceilings, per-model integer rates per million tokens, and ordered
request counters and admission labels. A per-request cost is rounded upward
with integer arithmetic. Only accepted requests count. A rejected request
does not consume the declared budget. An unknown or incomplete event makes
that event and all later cumulative totals `unknown`; the algorithm does not
guess how much budget remained after missing evidence.

`candidate_declared_budget_exceeded` means a declared cumulative request,
token, or computed micro-USD total exceeded its declared ceiling. It is not
provider billing, proof of cost abuse, or a chronological record. The event
order, counts, rates, ceilings, and admissions are not authenticated.

`analyze_supplied_agent_resource_budget` creates an unsigned report.
Verification requires a separately retained original model through
`verify_supplied_agent_resource_budget` or its bounded JSON-byte variant.
The report's embedded source cannot authenticate itself. The checked
synthetic envelope is `examples/offline-agent-resource-budget-component.json`.

No model, provider, agent, credential, file, network, or target is accessed.
The result grants no authority, finding, routing, candidate assembly, or
qualification.
