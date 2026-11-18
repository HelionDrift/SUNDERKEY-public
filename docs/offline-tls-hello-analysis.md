# Supplied TLS 1.3 Hello offer-selection analysis

This partial offline component compares two caller-supplied handshake messages.
It performs no endpoint, network, process, credential, provider or file operation.
The messages must include their Handshake type and uint24 body-length headers.
They must not contain TLS record or QUIC framing.

The component belongs to AOE-GE-D22-S02, capability army.ge.d22.s02, vector
AV-GE-D22-S02-01, work package IWP2-AOE-GE-D22-S02 and wave IW2-015. Its
component ID is tls13_supplied_hello_offer_selection. The commander is
AOE-GE-D22-CMD, group commander AOE-HQ-07 and independent validator AOE-HQ-19.
Its only initial roadmap mapping is A7.4. The blueprint binding is
sha256:74e096e4a79ded22370d7e799d27f894b20a5e49d05046e3c8fc51e34fef1457.
This implementation is not a completed, qualified or routable specialist.

## Closed supplied model and public API

The exact native model has three fields:

```json
{
  "schema_version": 1,
  "client_hello_base64": "canonical standard base64 of one ClientHello",
  "server_hello_base64": "canonical standard base64 of one ServerHello"
}
```

The base64 values use exact padding and padding bits. No whitespace, alternate
alphabet or inferred framing is accepted. The original bytes, including their
order, opaque share data and unknown offered identifiers, are retained in the
model. The raw JSON spelling is not retained: the model digest binds the parsed
canonical native snapshot, while the two message digests bind the exact bytes.

Public functions are:

- analyze_supplied_tls_hello_pair(model)
- analyze_supplied_tls_hello_pair_bytes(*, model_bytes)
- verify_supplied_tls_hello_analysis(report, *, model)

They return a frozen TlsHelloAnalysis with to_dict(), to_json(), from_dict() and
from_json(). Exports are detached native records. TlsHelloAnalysisError denotes
malformed intake, unsupported native families, exhausted software ceilings or
inexact report replay. It does not denote an observed TLS failure.

component_fixture() returns a fresh model containing fixed opaque synthetic share
bytes, not generated keys. No private key or cryptographic credential is needed.

## Supported arithmetic and structural observations

The parser respects Handshake body lengths and each vector's own boundary.
It records complete supported structure, truncated prefixes or concrete encoded
contradictions. confirmed_prefix_end is the offset reached before a failed field
or the end of a completely parsed message; it is not evidence that a peer sent
or accepted that prefix. Duplicate extension types and client key-share groups
are not collapsed. Checked extension payloads must consume their exact lengths.

For a completely parsed ordinary pair selecting TLS 1.3, the analyzer checks:

- Both legacy_version values are 0x0303; client compression is one zero byte and
  server compression is zero.
- The server session ID echoes the exact client bytes.
- The selected cipher and version occur in the supplied client offers.
- Client shares are an ordered, possibly noncontiguous subset of supported groups.
- The server share's group occurs in both client groups and client shares.
- Handled ServerHello extensions were offered in ClientHello and supported_groups
  does not appear in the ordinary ServerHello.

The supported structure follows [ClientHello](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.2),
[ServerHello](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.1.3),
[extensions](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2),
[supported versions](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.1),
[supported groups](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.7) and
[key shares](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.2.8).
The implementation is independently written, not copied from an upstream parser.

Unknown offered identifiers are not violations merely because they are unknown.
Selecting an unknown cipher or group retains exact membership observations but
withholds a complete supported conclusion. A future selected version is not
treated as TLS 1.3; its exact offer membership can still be checked. A prior
version selected through the supported_versions extension is a known
contradiction. Duplicate cipher and version offers are preserved. Duplicate
supported-group ordering is conservatively unassessed rather than normalized.

## Explicitly unassessed features

The HelloRetryRequest special random is inspected before ordinary ServerHello
key-share parsing. HRR is returned unassessed, without pretending its different
key-share payload is an ordinary server share. The remainder of HRR is not
validated. PSK declarations, unhandled extensions, absent TLS 1.3 selection,
future selected identifiers and unsupported ordering receive explicit reasons.
Known contradictions may remain alongside those reasons; they do not establish
full handshake validity or a vulnerability.

The outcome is one of consistent_with_supported_hello_selection,
violations_observed or unassessed. supported_checks_complete describes only this
closed supported projection. In particular, an opaque one-byte share can satisfy
the structural and membership projection without being a valid cryptographic key.
The analyzer does not validate key exchange bytes, randomness, full key schedules,
signature algorithms, PSK binders, extension-wide protocol semantics, transcript
or downgrade protection, certificates, trust, Finished, application data or live
endpoint behavior. It establishes neither authentication nor effective security.

## Finite software bounds and replay

Each message is at most 65,536 bytes. A supplied model is at most 262,144 raw or
canonical escaped bytes, and a complete report at most 1,048,576 canonical bytes.
An in-bound supplied header advertising a larger Handshake body is unassessed
without allocating or attempting that body; exceeding the actual intake ceiling
is a domain rejection.
Native and raw JSON have at most 8,192 values/keys and depth 16. Every native
string has at most 87,384 Unicode scalar characters. Native integers must fit
signed 64-bit representation; bool and float aliases are not integers.

Each Hello has at most 128 extensions, 256 cipher suites, 256 supported groups and
64 client shares. The protocol's one-byte supported-version vector permits at
most 127 versions. At most 64 combined violations/unassessed reasons are retained.
The operation charges a cumulative 4,194,304 work units for native capture,
escaped bytes, binary reads, base64, matching and reserved hash input bytes.
Queued structures and repeated subtrees are charged before expanding them.
Raw token, scalar, depth, node, canonical-escape and signed-integer limits are
checked before decoding. Duplicate JSON keys reject at every nesting level.
Floats, nonfinite numbers, malformed Unicode and nonnative wrappers reject.
Software exhaustion raises the domain error, not a fabricated protocol outcome.

The entire fixed-width report and domain-wrapped address input are natively
captured before canonical serialization or the first digest. A report embeds
the original model and re-derives every observation and fixed boundary when
parsed. Changing a conclusion and truthfully rehashing the metadata cannot pass
that replay. Separate-original verification additionally rejects an internally
consistent report made from different supplied bytes. Hashes prove local content
correlation, not source authenticity, ownership, TLS negotiation or timestamp truth.

Pre-entry valid source changes produce different reports. Immutable exported
records do not sandbox arbitrary caller code or prove that external memories
cannot change concurrently. There is no external callback in this component.
All authority, execution, target, provider, routing, qualification and deployment
effects remain none; live-use and qualification flags remain false.

## Inert acceptance checks

The focused tests use independent byte encoders and finite offer-set/ordered-subset
oracles. They cover ordinary literals and round trips; legacy, compression,
session, cipher, version and share contradictions; complete vector consumption;
all strict message prefixes; HRR and PSK; unknown identifiers and extensions;
exact byte/count ceilings; predecoder, preallocation and prehash denial; detached
ownership; coherently readdressed false reports and separately supplied originals.
No test connects to a TLS endpoint or asserts production qualification.
