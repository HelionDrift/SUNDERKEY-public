# Supplied Query Input Boundary

The `AOE-GE-D23-S01` partial specialist compares caller-declared query input
incorporation with a declared parameter-binding requirement. It records only
opaque input references, one of four broad query families, and whether
execution is asserted. If a complete model says untrusted input is interpolated
under a binding requirement and execution is declared, it reports a candidate
declared query-input boundary conflict.

The model does not accept or generate query text or injection payloads. It
does not parse a query, validate a driver, observe execution, or establish an
injection vulnerability. Unknown input trust or incorporation withholds a
candidate disposition. A construction conflict without declared execution is
kept separate from a candidate executed path.

The source is limited to 64 queries, 16 inputs per query, and 32 KiB. The
64 KiB report embeds the source for separate-source replay. No file, network,
process, credential, target, execution, publication, or qualification effect
occurs. The [synthetic example](../examples/offline-query-input-boundary-component.json)
uses labels and assertions only.
