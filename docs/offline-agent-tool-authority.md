# Supplied agent tool authority projection

This R0 partial component belongs to specialist `AOE-GD-D20-S14`, capability
`army.gd.d20.s14`, vector `AV-GD-D20-S14-01`, work package
`IWP2-AOE-GD-D20-S14`, and wave `IW2-004`. Its component ID is
`agent_supplied_tool_authority_projection`. It contributes only partial
offline evidence, not candidate assembly, qualification, routing, or live use.

The exact version 1 model contains separately labeled evidence sources, one
declared complete or incomplete policy, and finite tool-use declarations.
The policy lists exact opaque tool and resource IDs and a maximum R0, R1, or
R2 action tier. Each use declares its requested tier, an approval state,
context completeness, and a supplied admission outcome. These values are
caller declarations. Approval is not authenticated or transferable authority.
IDs are opaque and cannot carry a URL, path, command, payload, or credential.

With complete premises, the analyzer compares the requested tool, resource,
tier, and approval to the supplied policy. A supplied admission contradicting
a declared rejection becomes `candidate_declared_overreach`. A supplied
rejection contradicting a declared allowance is a separate availability
contradiction, not an overreach candidate. Unknown tool or resource labels,
approval, admission, or incomplete policy, context, or observation yields
`unknown` with reasons. No approval declaration authorizes actual use.

`analyze_supplied_agent_tool_authority` and its bounded JSON-byte variant
produce a deterministic, source-retaining report. `from_json` replays the
retained source but does not establish that it is the independently held
original. Consumers must use
`verify_supplied_agent_tool_authority(report, model=original_model)` before
using the result as supplied-source evidence. The checked synthetic envelope
is `examples/offline-agent-tool-authority-component.json`.

The analyzer performs no tool call, target interaction, network or provider
request, process execution, file access, credential resolution, finding
publication, qualification, or authority decision. A candidate is a supplied
declaration contradiction, not proof of excessive agency or live behavior.
