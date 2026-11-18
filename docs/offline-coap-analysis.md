# Supplied CoAP GET/ACK byte structure

This partial offline component belongs to `AOE-GD-D18-S15`, capability
`army.gd.d18.s15`, vector `AV-GD-D18-S15-01`, work package
`IWP2-AOE-GD-D18-S15`, and wave `IW2-019`. Its commander is
`AOE-GD-D18-CMD`, group owner `AOE-HQ-06`, and independent validator
`AOE-HQ-33`. The existing blueprint address is
`sha256:a3e9ff84eaf62017510d6009eb674c0e8790538e96ad8a9bd86a99b0c4c9af3b`.
The component ID is `coap_supplied_get_piggyback_structure`; this is an
explicit additional algorithm, not a replacement for the MQTT default.
Initial evidence is limited to A7.4. No specialist completion, qualification,
routing or deployment follows.

## Pure public interface

`src/sunderkey/offline_coap_analysis.py` provides:

- `analyze_supplied_coap(model) -> CoapAnalysis`
- `analyze_supplied_coap_bytes(*, model_bytes) -> CoapAnalysis`
- `verify_supplied_coap_analysis(report, *, model) -> CoapAnalysis`
- `CoapAnalysis(document_json)`, `from_dict`, `from_json`, `to_dict`, `to_json`
- `CoapAnalysisError` and fresh public `component_fixture()`

The exact source model has five fields:

```json
{
  "schema_version": 1,
  "request_source_id": "synthetic-get",
  "response_source_id": "synthetic-ack",
  "request_base64": "canonical padded standard base64",
  "response_base64": "canonical padded standard base64"
}
```

The displayed base64 descriptions are placeholders, not an executable example.
Use `component_fixture()` for actual independently interpretable inert bytes:
CON GET and ACK 2.05, MID 0x1234, opaque token AA, Accept 0,
Content-Format 0, and payload bytes 6F 6B. The labels are caller declarations,
not authenticated identities or endpoint coordinates. Empty base64 is permitted
as an explicitly truncated datagram observation. The function performs no IO.

Report records include `analysis_id`, `analysis_sha256`, complete
`source_model`, `source_model_sha256`, raw request/response byte lengths and
SHA256s, ordered option observations, payload hex, MID/token comparisons,
contradictions, and unassessed reasons. The address domains are separate:
`sunderkey.offline-coap-model.v1` and `sunderkey.offline-coap-analysis.v1`.
The analysis address has prefix `CPA-`.

## Selected semantics and deliberate uncertainty

The primary reference is [RFC7252](https://www.rfc-editor.org/rfc/rfc7252.html),
particularly [message format and option geometry](https://www.rfc-editor.org/rfc/rfc7252.html#section-3),
[matching](https://www.rfc-editor.org/rfc/rfc7252.html#section-5.3), and
[option processing](https://www.rfc-editor.org/rfc/rfc7252.html#section-5.4).
The implementation is independently written, not an endpoint implementation or
a copy of reference codec code.

Version-one parsing retains the four-byte header, token, delta-ordered options,
and opaque payload. Extended nibbles use offsets 13 and 269 and big-endian
extension octets. FF starts a payload only at an option boundary. Reserved
nibbles, token lengths 9 through 15, nonempty Empty messages, and a marker
without following payload produce selected format contradictions. Short
headers, tokens, extension fields and values are incomplete supplied prefixes.

Option uint values accept leading zero octets and retain their exact bytes.
RFC7252 Table 4 lengths and repeatability are projected. Response ETags have
a one-occurrence limit, unlike request ETags. A subsequent singleton, known
inapplicable option, or invalid option-length instance is unrecognized, not a
generic framing failure. Odd/even critical/elective classification remains
visible; no rejection or error response is sent. Unknown options withhold a
complete selected conclusion regardless of whether an endpoint might ignore
an elective option.

The pair projection is CON GET with a known piggyback ACK response code.
MID and token differences are declared-pair contradictions. An Empty ACK
retains its MID check but lacks response/token matching and leaves the missing
separate response unassessed. Nonpiggyback exchanges and unmodeled codes do
not inherit these checks. The selected 2.03 structure needs an ETag and no
payload; its representation-validation facts still remain unassessed.

String-option bytes are never decoded, normalized into URIs, resolved, or
claimed to satisfy Net-Unicode or URI syntax. Conditional and proxy facts,
uncertain applicability, GET payload meaning, cache state, extension semantics,
and response-content truth remain unassessed. A known response error is not
evidence that a real server rejected anything; success is not evidence of
actual access.

`consistent_supported_piggyback_structure` means only the selected structural
predicates. Other outcomes are `structural_contradictions_observed` and
`incomplete_or_unassessed`. All claims are false and all effects are `none`.
Even an otherwise consistent result does not establish shared endpoints,
traffic, source authentication, delivery, full RFC conformance or security.

## Finite software ceilings

| Resource | Ceiling |
| --- | ---: |
| Each supplied datagram | 8,192 bytes |
| Parsed source model / report | 32,768 / 262,144 canonical bytes |
| Native or raw nodes | 16,384 |
| Scalar-inclusive depth | 16 |
| Each metadata string | 16,384 ASCII characters |
| Options per datagram | 128 |
| Distinct reason codes per kind | 64 |
| Cumulative work per public operation | 16,777,216 charged units |

These are software limits, not CoAP size rules; simultaneous maxima need not
fit. Exact native types, signed64 integer grammar, cycles, repeated subtrees,
queued children, ASCII escapes and aggregate output are charged. Raw JSON
has lexical depth/node/string/integer preflight before decoding, closed
duplicate-key handling, and no float or nonfinite normalization. The decoded
datagram size is checked before base64 allocation. Option expansion is iterative
and count/value work is funded before retention.

Complete output, content hashes, address encodings and final equality work are
reserved before the first SHA256. All eight public paths share their operation
budget through replay. Separate-original verification plans both embedded and
independently supplied models before either is hashed. Cost exhaustion is a
`CoapAnalysisError`, not a fabricated protocol contradiction.

The frozen wrapper rederives its complete embedded source at construction,
parsing and export. Reports must be exact canonical JSON; malformed metadata
is not rehashed or repaired. The bytes-input model may have insignificant JSON
whitespace, so the model identity binds its canonical parsed snapshot, not raw
JSON provenance. Independent original verification also rejects a truthful
different source model. Exported records and public fixtures are detached.
Valid pre-entry source replacement, concurrent Python memory changes and
arbitrary caller-code isolation are not claimed to be prevented.

## Synthetic verification boundary

Tests use an independent endian/option encoder and explicit arithmetic expected
values. They cover extensions, FF inside values and extension octets, opaque
tokens/payloads, singleton and applicability rules, empty/separate exchanges,
prefixes, exact limits, source substitutions, cohashed false results and all
eight prehash work boundaries. Transparent reduced output/node caps test denial
placement with genuine finite source data; they are not described as a default
ceiling bypass. No live CoAP traffic or acceptance is inferred.

No socket, UDP/DTLS/TCP stack, polling, retry, discovery, multicast, provider,
credential, target, process, storage, publication or operational authority
interface is present.
