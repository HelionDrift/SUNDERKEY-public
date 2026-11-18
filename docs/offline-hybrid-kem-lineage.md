# Supplied Hybrid KEM Lineage

The GE-D22-S07 component projects whether caller-declared classical and
post-quantum contribution IDs both reach a declared final derivation. It accepts
at most 32 contributions, 32 derivations, and eight inputs per derivation.
Unknown material references and derivation cycles reject.

The model contains labels and edges, not key bytes. A graph containing both
declared contribution kinds does not validate an algorithm, KEM, key combiner,
handshake, or security property. The result cannot establish a finding,
qualification, or action authority.

The checked synthetic example is
[`examples/offline-hybrid-kem-lineage-component.json`](../examples/offline-hybrid-kem-lineage-component.json).
Verification requires replay against the separate original model.
