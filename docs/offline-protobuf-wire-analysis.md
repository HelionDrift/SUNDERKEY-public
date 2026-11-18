# Supplied Protobuf wire occurrences

This component scans actual supplied message bytes using a finite, separately
supplied local field projection. It retains original wire order, duplicate
occurrences, byte offsets, packed chunks and opaque unknown values. It does not
build a generated message object, execute an RPC or authenticate a schema.

## Existing ownership and selector

The explicit selector is protobuf_supplied_wire_occurrences under existing
profile AOE-GB-D06-S03, capability army.gb.d06.s03 and vector
AV-GB-D06-S03-01. Package IWP2-AOE-GB-D06-S03 stays in IW2-010 under
AOE-GB-D06-CMD and AOE-HQ-04, with independent validator AOE-HQ-34.
The existing schema-evolution default is unchanged. This source adds partial
A2.10 and A7.4 evidence, not a new expert, assembled candidate or accepted stage.

## Closed model

The exact model fields are schema_version:1, source_id, root_message,
messages and payload_base64. Source and message identities are bounded ASCII
labels, not endpoints or authenticated interface identities. Each local message
has exactly message_id and fields. Each field has exactly field_number,
field_type, repeated and message_type. Only message fields may name another
declared local message; other fields require null message_type. Message and
per-message field identities are unique. Original declaration array order is
retained even when conditional calculations are the same.

Supported declarations are uint32, uint64, int32, int64, sint32, sint64,
bool, fixed32, fixed64, sfixed32, sfixed64, string, bytes and message.
This finite projection is not a .proto compiler or a legal-schema validator.
In particular, a supplied field number in a compiler-reserved band is retained
as conditional wire arithmetic, not approved for compiler use. All nonzero
29-bit field numbers fit the supported tag projection.

## Actual byte arithmetic

The parser handles wire classes 0, 1, 2 and 5. It checks complete tag/value
boundaries, bounded unsigned varints, little-endian fixed-width values and
length-delimited subranges. Scalar varints have a ten-byte ceiling with a checked
64-bit final payload. Tags and lengths have a five-byte supported ceiling.
Nonminimal encodings that fit these bounds are retained, not normalized.

A repeated declared numeric field accepts unpacked values, multiple packed
chunks, empty packed chunks and interleaved fields in their original order.
Unknown length-delimited values stay opaque. Only a matching supplied message
declaration enables recursion. Each nested row refers to its exact parent
occurrence index, not a guessed object or target. These selected encodings follow
the primary [Protobuf encoding guide](https://protobuf.dev/programming-guides/encoding/).

Unsigned wire values and decoded signed numbers use bounded decimal text so
full-width uint64 values do not alias signed-int64 JSON values. Numeric values
outside the selected typed subset retain raw arithmetic and withhold their typed
interpretation. Boolean wire values other than zero and one are outside this
component's selected typed subset, not a generic claim of malformed Protobuf.
Strict UTF-8 validation is conditional on a supplied string declaration; output
retains original bytes and a validity observation without Unicode normalization.

Duplicate singular fields are not collapsed, nested messages are not merged,
and no absent/default-field conclusions are inferred. See the primary
[field-presence guidance](https://protobuf.dev/programming-guides/field_presence/).
Groups, enums, floating-point interpretation, maps, oneof, compiler object
semantics and gRPC framing are outside this implementation.

## Replay and output

Public APIs are analyze_supplied_protobuf_wire(model),
analyze_supplied_protobuf_wire_bytes(*, model_bytes) and
verify_supplied_protobuf_wire_analysis(report, *, model). They return a frozen
ProtobufWireAnalysis. Its direct constructor, from_dict, from_json, to_dict
and to_json all replay the complete embedded original model before returning
a detached report. The separate-original verifier is still required whenever
the independently supplied original matters. A valid internally coherent report
for another source does not verify against the old original.

The unsigned PWA- result binds the complete original model, exact payload bytes,
conditional observations and fixed ownership/effects. It is not a semantic
message-object fingerprint. Different encodings of the same interpreted value
remain different source identities. Deterministic Protobuf serialization is not
general canonical object serialization, as the primary
[serialization guidance](https://protobuf.dev/programming-guides/serialization-not-canonical/)
explains. No report digest authenticates data acquisition, schema truth or a target.

## Finite software costs

Payloads have a 256 KiB ceiling; models 1 MiB and reports 2 MiB. There are at most
64 message declarations, 4096 aggregate fields, 16384 wire occurrences, 65536
packed scalar values and 16 actual message levels. Native model/report node
ceilings are 32768/262144 with scalar-inclusive depth 16, signed-int64 integers,
exact native JSON families and bounded ASCII text. Duplicate raw JSON keys,
cyclic native containers, aliases through subclasses, floats and nonfinite
numbers are rejected. Raw lexical, node, string, byte and depth ceilings precede
JSON decoding. Shared native subtrees are charged on every occurrence.

A public pass has one cumulative 128 MiB work budget for its own traversal,
copying, wire scanning, retained observations, serialization, replay and digest
bytes. Derived retention has a separate 1 MiB conservative ceiling; packed values
are charged both as individual retained values and inside their owning row.
Consequently individual advertised maxima need not fit simultaneously.
All remaining report retention, encoding, address and full-comparison work is
funded before the first digest. Separate-original verification prepares both
complete source plans before either is hashed.

These are finite software limits, not claims that rejected inputs are malicious,
universally invalid Protobuf or impossible for another implementation.

## Excluded effects

All network, provider, credential, process, execution, publication, authority,
qualification and deployment effects remain none. No supplied bytes are sent,
no code is generated or invoked, and no callback or dynamic decoder is loaded.
No full specialist, review acceptance, runtime safety, vulnerability, live-use
authority, interface reachability or competitive parity follows from this leaf.
