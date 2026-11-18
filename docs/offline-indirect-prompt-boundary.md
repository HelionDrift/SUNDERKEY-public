# Supplied Indirect Prompt Boundary

This R0 partial component belongs to specialist `AOE-GD-D20-S10`, capability
`ai.indirect-prompt-injection`, vector `AV-GD-D20-S10-01`, work package
`IWP2-AOE-GD-D20-S10`, and wave `IW2-014`. The domain commander is
`AOE-GD-D20-CMD`; the independent validator reference is `AOE-HQ-35`.
It is one offline algorithm, not a complete candidate or qualified agent.

The bounded version 1 model declares content channels and trust labels,
destination context roles, and whether a source was admitted with its data
boundary preserved or promoted. It accepts no prompt, retrieved document,
instruction, model output, payload, credential, URL, or target response.
An accepted promotion of declared untrusted content into a declared
instruction or system context is a
`candidate_declared_lower_trust_promotion`. This is a caller-declared
trust-boundary conflict, not proof of a successful prompt injection.

Unknown channels, trust, roles, boundary states, admissions, or incomplete
context yield `unknown`. Rejected promotions, data-only contexts, preserved
boundaries, and declared trusted sources remain distinct non-candidates.
Neither trusted nor preserved labels authenticate a source or prove effective
isolation.

`analyze_supplied_indirect_prompt_boundary` produces an unsigned report.
Verification requires a separately retained original model through
`verify_supplied_indirect_prompt_boundary` or its bounded JSON-byte variant.
The report's embedded model cannot authenticate itself. The checked synthetic
envelope is `examples/offline-indirect-prompt-boundary-component.json`.

No model, agent, tool, interpreter, file, provider, network, or target is
invoked. No authority, finding, routing, candidate assembly, or qualification
is granted.
