# Supplied RAG Index Provenance

This R0 partial component belongs to specialist `AOE-GD-D20-S11`, capability
`army.gd.d20.s11`, vector `AV-GD-D20-S11-01`, work package
`IWP2-AOE-GD-D20-S11`, and wave `IW2-015`. Its commander is
`AOE-GD-D20-CMD`, and its independent validator reference is `AOE-HQ-35`.
It is not a complete candidate, qualified specialist, or live assessment.

The exact version 1 model has caller-supplied expected and indexed SHA-256
labels for bounded document records, approval labels, and declared retrieval
and incorporation outcomes. It accepts no document content, prompt, query,
model output, index connection, URL, credential, or target response.

An incorporated document with a different declared indexed digest is a
`candidate_declared_index_digest_mismatch`. An incorporated document with
declared denied approval is a `candidate_declared_unapproved_retrieval`.
Unknown expected digests, approval or use labels, and incomplete context
produce `unknown`. A retrieved but unincorporated document is a separate
non-candidate. A matching digest is only a declared match, not authenticated
provenance. If approval denial and digest mismatch coexist, the denial
disposition takes precedence; the complete original model remains in the
report for review.

`analyze_supplied_rag_provenance` produces an unsigned report. Verification
requires a separately retained original model through
`verify_supplied_rag_provenance` or its bounded JSON-byte variant. The
report's embedded model cannot authenticate itself. The checked synthetic
envelope is `examples/offline-rag-provenance-component.json`.

No retrieval, model, agent, provider, file, network, or target action occurs.
The result grants no authority, finding, routing, candidate assembly, or
qualification. Candidate status is a declaration discrepancy, not proof of
RAG poisoning or downstream influence.
