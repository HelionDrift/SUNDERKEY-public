# Supplied DNS message structure

This pure component analyzes one explicitly supplied DNS message. It does not
send, receive, resolve or authenticate DNS data. No endpoint, principal,
credential, clock, socket, provider or runtime is accepted. The report includes
the supplied message in base64, so it is not secret sanitization or a safe-to-
publish determination.

## Existing specialist scope

The component is `dns_supplied_wire_structure`, a partial algorithm for the
existing DNS, DHCP and IPAM lane:

| Binding | Exact value |
| --- | --- |
| Profile | `AOE-GC-D13-S03` |
| Capability | `army.gc.d13.s03` |
| Vector | `AV-GC-D13-S03-01` |
| Work package | `IWP2-AOE-GC-D13-S03` |
| Wave | `IW2-006` |
| Commander | `AOE-GC-D13-CMD` |
| Group commander | `AOE-HQ-05` |
| Independent validator | `AOE-HQ-19` |
| Roadmap package | `A7.4` |

The blueprint SHA is
`sha256:7ad8506c3f311239fe02108aa7905a21c74afb845bdc6594307294824b0b6bba`.
This is not implementation of the entire lane, DHCP, IPAM or a qualified
specialist. It changes no routing, deployment, qualification or authority gate.

## Closed model and APIs

```json
{"schema_version":1,"message_base64":"AAABAAAAAAAAAAAA"}
```

`message_base64` is canonical standard base64 of one nonempty message, without
IP, UDP, TCP or capture framing. `schema_version` must be the native integer 1.
No extra input fields are accepted.

```python
from sunderkey.offline_dns_message_analysis import (
    DnsMessageAnalysis,
    analyze_supplied_dns_message,
    analyze_supplied_dns_message_bytes,
    verify_supplied_dns_message_analysis,
)

report = analyze_supplied_dns_message(model)
same = analyze_supplied_dns_message_bytes(model_json=ascii_json_bytes)
parsed = DnsMessageAnalysis.from_json(report.to_json())
verified = verify_supplied_dns_message_analysis(report, model=model)
```

The byte API accepts exact native ASCII JSON bytes or text with duplicate-key
rejection. Source provenance binds the canonical parsed model and separately
the exact decoded message bytes. It does not bind the original JSON spelling.
The test `component_fixture()` returns a fresh `{"model": ...}` payload.

## Supported computation

The parser reads the 12-byte header and its counted sections. It preserves
record order, duplicates, unsigned flags and TTLs. Labels remain binary,
case-preserving base64 lists rather than ambiguous dotted names. Ordinary
labels have at most 63 octets; expanded names have at most 255 octets.

Compression expansion is iterative. Only prior proven label, root or
pointer-name boundaries are followed. Header, interior, self, forward and
out-of-message references cannot yield a consistent result. A name-looking
sequence in opaque RDATA is not a proven boundary. Encoded field consumption
and expanded lengths are accounted separately.

The IN subset is A (4 octets), AAAA (16), NS/CNAME/PTR (one name), MX (unsigned
16-bit preference and name), SOA (two names and five unsigned 32-bit fields),
and TXT (one or more binary character strings). An empty TXT character string
is supported; zero character strings contradict this subset. RDATA grammar
must consume exactly RDLENGTH. Unknown RDATA remains opaque.

Normative format sources are [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html)
sections 2.3.4, 3.1, 3.3 and 4.1,
[RFC 3597](https://www.rfc-editor.org/rfc/rfc3597.html) sections 3-4, and
[RFC 3596](https://www.rfc-editor.org/rfc/rfc3596.html) section 2.
The implementation is independently written, not copied from a resolver.

## Results and limitations

`supported_checks_outcome` is `consistent_supplied_subset`, `incomplete` or
`contradictions`. These are software observations, not comprehensive DNS
validity, safety or authority decisions. Observations distinguish supported
structural contradictions, physically truncated prefixes and unassessed
semantics, with offsets. Completed earlier questions and records remain
available if later parsing stops. `confirmed_prefix_end` ends after the last
complete retained entry; it is not the furthest byte examined.

`counted_sections_complete` only states that all declared entries were
consumed. Unknown class/type semantics, unknown opcode, extension flags, TC
and trailing octets still prevent a consistent-subset result. Unknown opcodes
stop after the header rather than applying standard-query semantics. The
one reserved header bit is checked separately from unassessed AD/CD flags.
Unconsumed suffixes are not parsed as another message.

The report proves no EDNS, DNSSEC, delegation, bailiwick, resolver, cache,
timestamp, TTL validity, query/response correlation, provider fact or target
behavior. Declared flags are not authenticated facts. No vulnerability, live
admission, human acceptance or qualification is established. All seven effect
fields are fixed to `none`; all authenticity, comprehensive-validity,
vulnerability, live-use and qualification booleans remain false.

## Finite software ceilings

| Resource | Ceiling |
| --- | ---: |
| Decoded message bytes | 65,535 |
| Model JSON bytes | 131,072 |
| Report JSON bytes | 1,048,576 |
| Native nodes / depth | 32,768 / 16 |
| Questions / total records | 64 / 256 |
| Names | 832 |
| Pointer hops per name | 32 |
| Proven name boundaries | 4,096 |
| Aggregate expanded name octets | 131,072 |
| Charged parser work | 262,144 |
| Aggregate TXT strings | 1,024 |
| Observations | 512 |

Count and encoded-size checks precede section loops and base64 decoding.
Raw JSON node, depth and signed64 integer lexical checks precede the JSON
decoder. Only exact native JSON families are captured; floats, nonfinite
numbers, primitive subclasses, cycles and non-ASCII metadata are rejected.
Repeated shared native subtrees are charged separately.

The parser charges byte, label, pointer, boundary and record work; expansion
is charged before retaining a label. Retained construction fragments are
conservatively charged again inside their parents. The complete source and
report, including fixed-width address placeholders, are bounded before the
first source/report hash or output serialization. Cost exhaustion raises
`DnsMessageAnalysisError`; it is not called malformed DNS or retried. These
finite implementation limits are not an observed performance benchmark or a
claim to support every legal message.

## Replay and acceptance

`DnsMessageAnalysis` owns canonical text in a frozen record and returns
detached documents. Every export and parse replays the full embedded model,
not just the outer hash. Coherently rehashed false parse facts are rejected.
A genuine alternate message can have a valid report; only verification
against the separately supplied original model establishes that exact source
correlation. Neither path authenticates who supplied the bytes.

The inert tests use a separately written binary encoder and compression
equivalence oracle, exact size boundaries, typed RDATA, binary labels,
truncations, hostile pointers, opaque data, count/cost limits and canonical
identity controls. No resolver or independent host evidence is substituted.
Caller code or storage can change data outside this component; no arbitrary
Python isolation, rollback, transport undo or concurrent-source guarantee is
claimed.
