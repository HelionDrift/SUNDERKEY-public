# Supplied Agent Memory Provenance

This R0 partial component belongs to specialist `AOE-GD-D20-S16`, capability
`army.gd.d20.s16`, vector `AV-GD-D20-S16-01`, work package
`IWP2-AOE-GD-D20-S16`, and wave `IW2-018`. Its commander is
`AOE-GD-D20-CMD`, and its independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The exact version 1 model contains caller-supplied memory-entry writer kinds,
approval labels, expected and stored SHA-256 labels, and declared read
admissions and context roles. It accepts no memory content, prompt, agent
message, MCP/A2A payload, credential, URL, or target response.

An accepted privileged-context read of an entry with declared denied writer
approval is a `candidate_declared_denied_memory_use`. A declared expected to
stored digest mismatch is a `candidate_declared_memory_digest_mismatch` when
the read was accepted into an instruction or tool-policy context. Denied
approval takes precedence if both discrepancies are present. Unknown writer,
approval, expected digest, context, admission, or incomplete context produces
`unknown`. Rejected and data-only reads are distinct non-candidates.

`analyze_supplied_agent_memory_provenance` creates an unsigned report.
Verification requires a separately retained original model through
`verify_supplied_agent_memory_provenance` or its bounded JSON-byte variant.
The report's embedded source cannot authenticate itself. The checked
synthetic envelope is
`examples/offline-agent-memory-provenance-component.json`.

No memory store, agent, tool, provider, file, network, or target is accessed.
The result grants no authority, finding, routing, candidate assembly, or
qualification. Candidate status is a declaration discrepancy, not proof of
memory poisoning or inter-agent compromise.
