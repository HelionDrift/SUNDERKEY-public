# Offline Protobuf schema-evolution analysis

This leaf supplies a partial deterministic analysis algorithm for
`AOE-GB-D06-S03`, capability `army.gb.d06.s03`, vector
`AV-GB-D06-S03-01`. It does not complete the specialist blueprint, implement
an RPC adapter, execute requests, or supply live evidence or qualification.

## API and sources

`analyze_protobuf_schema_evolution` takes keyword-only `previous_content` and
`current_content` native UTF-8 bytes, `previous_source_id` and
`current_source_id` native bounded identifiers, and explicit
`ProtobufAnalysisLimits`. `verify_protobuf_schema_evolution` takes those same
inputs plus keyword-only `report` and reparses both supplied sources to
reproduce the entire report. No files, callbacks, clocks, providers, credentials,
RPCs, process tools, imports, or runtime resources are read by this leaf.

Limits have no defaults: `max_previous_bytes` and `max_current_bytes` are
1..1,048,576 bytes each; `max_tokens` and `max_nodes` are 1..50,000 per source;
`max_observations` is 1..2,048. AST nodes count the syntax/package declarations,
messages, services, fields, RPCs, and each reserved interval or name. These are
local software-cost limits, not server cost estimates or operational budgets.
Report/native documents have a separate fixed 1 MiB canonical JSON budget,
depth 32, 50,000 visited nodes, 8,192 ASCII characters per string, and signed
63-bit integer-magnitude limit. Repeated shared subtrees and JSON escapes are
charged before serialization. An excessive result fails, never returns a
partial report. Numeric intervals are never expanded into field-number sets.

## Closed source subset

The source must begin, after whitespace/comments, with `syntax = "proto3";`.
One optional package declaration precedes the top-level definitions. Messages
and services can be forward referenced. Messages support all builtin scalar
types and local top-level message types, unlabeled/`optional` singular fields,
`repeated` fields, positive decimal tags, and reserved number intervals and
names. Ranges use inclusive `N to M` or `N to max`; adjacent intervals normalize
to one compact interval. Overlapping/duplicate ranges and names are rejected.
Tags are 1..536,870,911, excluding implementation-reserved 19,000..19,999 for
fields. A field cannot use a name or number reserved in the same schema.

Types resolve only as a bare local message name or an absolute
`.package.Message` name (or `.Message` without a package). Relative qualified
references are refused, not guessed. Recursive local message references are
legal and are not recursively expanded. Services support semicolon-terminated
RPCs with local request/response messages and independent `stream` modifiers.
Names use an ASCII letter followed by up to 127 ASCII letters, digits or
underscores. Keywords/scalar names cannot be identifiers in this subset.
Qualified names are at most 256 characters. Line and nonnested block comments,
including UTF-8 comment text, and empty statements are supported. Syntax and
reserved names use unescaped double-quoted literals only.

Imports, options (including field/RPC options), enums, maps, oneof, nesting,
extensions, groups, proto2, editions, quoted escapes/concatenation, single
quotes, signed/hex/octal numbers, and other unsupported syntax fail closed.
This is not a `protoc` replacement or a full compiler-validity claim. The
official specification itself notes that its grammar is not definitive for
every compiler lexical nuance.

## Observations and replay

Fully qualified top-level message/service names are joined across revisions.
Added/removed top-level definitions carry summaries, without inventing child
removal observations. Matched messages join field names and numbers separately.
Observations include added/removed fields, renumbering, a changed name at a
number, type/base-wire-class changes, cardinality and presence changes, deleted
numbers/names without a current reservation, released/added reservations, and
current fields using prior reserved numbers/names. A changed name at a tag is
not proof of malicious semantic reuse; its type, cardinality and presence joins
are also retained at that tag. Reservation differences are computed by
compact interval subtraction. Matched services join RPC names and compare
request/response message names and both streaming flags.

Singular message fields always have explicit presence, so adding `optional`
to a message field is not reported as a presence change. Scalar optional versus
implicit presence is distinguished. Repeated numeric/bool scalars are marked
packed by default, while strings, bytes and message fields are not. The
`base_wire_type` metadata describes a scalar or submessage's unpacked wire
class, not a complete repeated-field encoding or compatibility verdict. A
shared wire class does not establish semantic compatibility (for example,
ZigZag versus ordinary varints, or strings versus bytes).

`ProtobufAnalysisReport` contains detached metadata only, never source text or
payload bytes. `to_dict` returns a new validated document; `to_json` is canonical
JSON. Schema version 1 uses domain `sunderkey.offline-protobuf-analysis.v1`,
`PBA-` ID and SHA-256. Exact raw source SHA/length/IDs, caller limits, statistics,
and sorted unique observations are bound. Comments/declaration permutations
can preserve observations but change source hashes and report identity.
`from_dict`/`from_json` establish bounded unsigned metadata/content-address
integrity only. Duplicate JSON keys, floats, nonfinite numbers, native aliases,
unknown fields and malformed wrappers are rejected. A coherently rehashed false
observation can still be unsigned metadata; full source/config replay is the
required check before treating it as this analyzer's output.

All outputs remain offline-only, with positive-use, qualification, wire
compatibility certification and verified security-findings flags false and
authority/target/execution/routing/qualification/deployment effects `none`.
No source authenticity, complete compatibility, vulnerability, exploit,
denial-of-service, runtime deployment, or target permission is inferred.
Python privacy is not a sandbox for arbitrary concurrent in-process mutation.

## Primary references and tests

The closed grammar follows the supported portions of the official
[proto3 specification](https://protobuf.dev/reference/protobuf/proto3-spec/).
Field identity, reservation, presence and packed defaults are based on the
[proto3 language guide](https://protobuf.dev/programming-guides/proto3/).
Wire-class observations use the official
[encoding reference](https://protobuf.dev/programming-guides/encoding/), not
an overall safety inference. Inputs are supplied local descriptions only.

`tests/agents/test_offline_protobuf_analysis.py` uses inert byte fixtures,
literal result/source identities, exact replay and readdressed false reports,
presence and streaming controls, compact maximum ranges, malformed/unsupported
sources, wrapper/native type controls and pre-serialization cost limits.
No live endpoint, compiler process, provider or qualification evidence is used.
