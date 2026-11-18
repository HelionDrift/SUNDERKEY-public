# Supplied Modbus TCP read-exchange structure

`sunderkey.offline_modbus_tcp_analysis` performs bounded arithmetic over exactly
one supplied request ADU and one supplied response ADU. It does not transmit
messages, open a connection or interact with a controller. All examples are
synthetic. An address or decoded value does not establish an actual PLC map,
device state, vulnerability, process safety or authority.

The partial component is `modbus_supplied_tcp_read_exchange_structure`, owned by
`AOE-GD-D19-S06`, capability `army.gd.d19.s06`, vector `AV-GD-D19-S06-01`, package
`IWP2-AOE-GD-D19-S06` and existing wave `IW2-016`. Its domain commander is
`AOE-GD-D19-CMD`, group commander is `AOE-HQ-06` and independent validator is
`AOE-HQ-33`. The blueprint binding is
`sha256:d5e11b6e2210e57a627a4b7da3c0ad7036434345cb9246b6a3059b7011d43e41`.
Initial roadmap evidence is A7.4 only. No specialist package, candidate,
qualification, routing or deployment state is completed by this calculation.

## Primary definitions

The supported projection is pinned to the Modbus Organization's
[Application Protocol Specification V1.1b3](https://www.modbus.org/file/secure/modbusprotocolspecification.pdf),
sections 4.1, 4.2, 6.1 through 6.4 and 7, and
[Messaging on TCP/IP Implementation Guide V1.0b](https://www.modbus.org/file/secure/messagingimplementationguide.pdf),
sections 3.1 and 4.4.1.3. The implementation is independently written; it does
not copy implementation code from a protocol library or controller.

The input is an ADU, not a TCP segment, stream, RTU frame or serial capture.
Pairing and routing context are supplied declarations. The analyzer cannot
establish that the two messages used one connection or came from any device.

## Closed input and public API

```json
{
  "schema_version": 1,
  "routing_context": "bridge",
  "request_base64": "EjQAAAAGAQMAawAD",
  "response_base64": "EjQAAAAJAQMGAisAAABk"
}
```

These four fields are required; additional fields are rejected.
`schema_version` is the exact native integer 1, not a boolean or float.
`routing_context` is exactly `direct`, `bridge` or `unknown`. Both byte fields
are exact native strings containing canonical standard base64, with no spaces,
URL-safe alphabet, redundant padding or nonzero unused base64 bits. Empty byte
strings are permitted as supplied truncated prefixes, not valid ADUs.

The public functions are:

- `analyze_supplied_modbus_tcp(model)`
- `analyze_supplied_modbus_tcp_bytes(*, model_bytes)`
- `verify_supplied_modbus_tcp_analysis(report, *, model)`
- `component_fixture()`, returning a fresh synthetic model

The immutable `ModbusTcpAnalysis` wrapper exposes `from_dict`, `from_json`,
`to_dict` and `to_json`. `ModbusTcpAnalysisError` is the domain rejection for
malformed software inputs, unsupported native shapes, exceeded ceilings and
inconsistent replay. No API writes a file, performs a callback or discovers a
resource.

## Checked structure

The seven-byte MBAP header is decoded in big-endian order. Its unsigned length
includes the Unit Identifier and PDU, not the first six header bytes. The
analyzer compares the declared ADU endpoint with the supplied bytes. Missing
header or declared bytes are truncated/unassessed prefixes. A length below
Unit Identifier plus function, an endpoint above 260, or trailing bytes after
the declared ADU are structural contradictions. Trailing bytes are never
interpreted as another message.

Protocol Identifier zero enables the Modbus PDU projection. Other identifiers
are preserved and unassessed, not treated as ordinary Modbus. Request function
zero and exception-bit request functions are known contradictions. Other
functions, including write functions, are outside this read projection.

FC01 and FC02 require a five-byte request PDU and quantity 1 through 2000.
FC03 and FC04 require the same request width and quantity 1 through 125. The
starting address and requested last address are unsigned arithmetic. Crossing
the 16-bit address space is a contradiction; fitting that space does not prove
that a device implements any of those addresses.

For an ordinary supported response, its byte count must equal both supplied
payload length and the requested amount: ceiling(quantity / 8) for bit reads,
or twice quantity for register reads. Bit positions are decoded low-bit first;
unused high bits in the final partial byte must be zero. Registers are decoded
as unsigned 16-bit big-endian integers. Values are only supplied observations;
there is no application interpretation, signedness inference or state proof.

An exception response must contain exactly the exception function and one code.
The exception function must equal request function plus 128. Codes 1 through 4
are within the selected FC01 through FC04 projection. Other codes are retained
as unassessed, including globally defined specialized or gateway codes; this
does not declare them universally invalid. An exception is never a successful
read, nor proof that the stated remote error actually occurred.

Transaction IDs are compared exactly. Equality is a supplied-pair join, not
proof of a pending transaction or shared TCP connection. No replay window,
response deadline or current device authority is inferred.

### Unit Identifier context

The implementation guide discards Unit Identifier for a directly connected TCP
server, while it identifies a remote server behind a bridge or gateway.
Consequently:

- `direct`: retain field equality as an observation, but ignore mismatch for
  correlation. No universal Unit Identifier equality or preferred-value rule
  is invented.
- `bridge`: require equality under this supplied routing premise. The premise
  does not authenticate the topology, identify a physical slave or validate a
  serial address assignment.
- `unknown`: preserve equality or mismatch, and withhold a comprehensive
  supported-structure conclusion. Mismatch alone is not a contradiction.

## Outcomes and provenance

The result contains exact `analysis_id`, `analysis_sha256`, `source_model`,
`source_model_sha256`, request/response byte hashes and lengths, decoded fields,
correlation checks, contradictions and unassessed reasons. The outcomes are:

- `consistent_supported_read_structure`
- `consistent_supported_exception_structure`
- `structural_contradictions_observed`
- `incomplete_or_unassessed`

Known contradictions remain visible even when some other semantics are
unassessed. `supported_checks_complete` describes availability of the supported
frame/request projection without unassessed reasons; it is not a passing check,
success, authenticity or authority flag. Contradictions can coexist with it.
Use the outcome and full observations rather than promoting a single boolean.

The source-model digest is domain-separated over canonical parsed JSON. It is
not a hash of the original JSON intake bytes: different field order or spacing
can produce the same source-model identity. Separate request and response SHA256
values bind their exact decoded binary bytes. All hashes are unsigned content
identities, not authenticated capture or custody.

Construction and every export rederive the whole result from the embedded
source. Canonical report JSON must replay exactly; malformed reports are not
normalized, repaired or rehashed. `from_dict` accepts a native representation
whose canonical serialization must match the derived report. A coherently
rehash-addressed false result is rejected.

A valid alternate source can create a different valid report. Only
`verify_supplied_modbus_tcp_analysis(report, model=original)` joins a report to
the separately supplied original model. Even that check proves local source
consistency, not source authenticity, live currentness or permission.

## Software ceilings and ordering

| Ceiling | Value |
| --- | ---: |
| Supplied ADUs | Exactly one request and one response |
| Decoded bytes per ADU | 260 |
| Model JSON bytes | 16,384 |
| Retained report JSON bytes | 131,072 |
| Native or raw nodes per document | 8,192 |
| Native or raw depth, counting scalar leaves and keys | 16 |
| Decoded ASCII string characters | 2,048 |
| Contradictions or unassessed reasons per kind | 32 |
| Cumulative public-operation work units | 4,194,304 |
| Native and raw integers | Signed 64-bit, exact native integer |

Source base64 strings have the additional exact bound needed for 260 decoded
bytes. The closed JSON projection is ASCII; arbitrary binary payload bytes are
preserved through base64. Native float/subclass aliases, cycles, duplicate JSON
keys, malformed UTF-8 and out-of-range integers are domain rejections.

The lexical scanner bounds raw containers, scalar leaves, strings and integer
tokens before JSON decoding. Repeated shared native containers are charged for
each retained occurrence. Parsing/decoding, complete output capture, subsequent
replay, final serialization/equality and all source/byte/report hashes are
funded cumulatively before the first digest in each public operation. Separate
original verification funds both derivative plans and their comparison before
either plan is hashed. A software ceiling is a domain rejection, not a claimed
protocol contradiction or remote failure.

The small source subset can fit production output limits. Reduced-limit tests
exercise retained byte/node denial and exact work boundaries transparently;
they do not claim the default limits were bypassed. Not every hypothetical
maximum combination is promised to fit all limits.

## Tests and exclusions

Owned tests use a separately written endian encoder, bit/register tables,
quantity bounds, every proper fixture truncation, exception/function/transaction
substitutions and all three Unit Identifier contexts. They cover the 260/261
byte boundary, raw predecoder limits, native aliases, false readdressed results,
separate original-source substitution, fresh detachment and every public
operation's prehash cumulative work funding.

There is no device adapter, Modbus engine, network request, target interaction,
credential use, write request, RTU/serial/CRC parsing, TCP reassembly, stream
pairing, retry, scheduling or physical-process model. DNP3, OPC UA, EtherNet/IP,
other Modbus functions, vendor behavior and full protocol conformance are not
implemented by this partial component. All effects remain `none`, all authority
and qualification claims remain false, and existing live-use gates stay intact.

Immutable native ownership detects the documented retained substitutions; it
does not sandbox arbitrary Python callbacks or guarantee isolation against
concurrent memory mutation. No storage, rollback, independent-host custody or
authenticated evidence claim is made.
