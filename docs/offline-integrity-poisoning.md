# Supplied Artifact Integrity and Consumption

The `AOE-GE-D23-S15` partial specialist compares two supplied SHA-256 digest
strings, a declared origin-trust state, an explicit digest-match policy, and
a declared consumption decision. A mismatch under a require-match policy and
an allow decision is a candidate declared integrity conflict. When the origin
is also declared untrusted, it is classified as a candidate declared
untrusted-content consumption. Neither disposition verifies poisoning.

The model does not read or hash artifact bytes, validate a trust root, observe
consumption, or contact a target. Unknown origin or outcome and incomplete
capture withhold candidate dispositions. Digest strings are syntax-checked
caller assertions, not independently measured evidence.

The source is limited to 128 artifacts and 32 KiB. The 64 KiB report embeds
the source for separate-source replay. No file, network, process, credential,
target, execution, publication, or qualification effect occurs. The
[synthetic example](../examples/offline-integrity-poisoning-component.json)
uses inert labels and literal digest strings.
