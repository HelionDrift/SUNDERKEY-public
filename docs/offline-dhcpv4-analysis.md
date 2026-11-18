# Supplied DHCPv4 packet structure and declared pairs

`dhcpv4_supplied_offer_ack_structure` performs inert byte analysis on two supplied
packets. It is not a client, server, relay, network capture, IPAM allocator,
lease inspector or rogue-server detector. It has no socket, clock, callback,
provider, process, credential or source-acquisition interface. Retained opaque
bytes are not sanitized or approved for publication.

## Existing lane

This is partial `A7.4` evidence in the existing DNS, DHCP and IPAM specialist:

| Binding | Value |
| --- | --- |
| Profile | `AOE-GC-D13-S03` |
| Capability | `army.gc.d13.s03` |
| Vector | `AV-GC-D13-S03-01` |
| Work package | `IWP2-AOE-GC-D13-S03` |
| Wave | `IW2-006` |
| Commander / group | `AOE-GC-D13-CMD` / `AOE-HQ-05` |
| Independent validator | `AOE-HQ-19` |
| Blueprint | `sha256:7ad8506c3f311239fe02108aa7905a21c74afb845bdc6594307294824b0b6bba` |

The explicit selector does not replace the existing DNS default or establish
the whole lane, a candidate, qualification, live permission or operational
readiness. The leaf itself changes no catalog or shared dispatcher.

## Closed inputs and interfaces

The exact model has five fields:

```json
{"schema_version":1,"request_source_id":"synthetic-discover","response_source_id":"synthetic-offer","request_base64":"...","response_base64":"..."}
```

Both base64 strings are nonempty canonical standard base64 containing the
BOOTP/DHCP packet only, without IP, UDP or link framing. The two source IDs
are printable ASCII labels matching `[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}`. They
are not endpoints or authenticated producers. `schema_version` is native
integer 1, not `true` or a floating alias. No extra fields are accepted.

```python
from sunderkey.offline_dhcpv4_analysis import (
    Dhcpv4Analysis,
    analyze_supplied_dhcpv4,
    analyze_supplied_dhcpv4_bytes,
    verify_supplied_dhcpv4_analysis,
)

report = analyze_supplied_dhcpv4(model)
same = analyze_supplied_dhcpv4_bytes(model_bytes=ascii_json_bytes)
parsed = Dhcpv4Analysis.from_json(report.to_json())
verified = verify_supplied_dhcpv4_analysis(report, model=original_model)
```

`component_fixture()` returns a fresh five-field model containing wholly
synthetic literal DISCOVER/OFFER bytes. It requires no test module or acquired
packet. The canonical source address ignores raw JSON member order and
whitespace; each decoded packet also has an exact SHA256 byte identity.
These hashes are unsigned content bindings, not packet authentication.

## Actual supported computation

The primary sources personally reviewed for this independently written
algorithm are [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html) sections
2, 3 and 4.1, Tables 3-5;
[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html) sections 2, 3.1-3.2
and 9.1-9.7/9.14; and
[RFC 3396](https://www.rfc-editor.org/rfc/rfc3396.html) sections 4-7.

The parser reads the 236-byte fixed header and four-byte DHCP cookie. Fixed
numeric fields use network byte order. Address fields, all sixteen `chaddr`
octets and the `sname`/`file` bytes are retained as exact hexadecimal text.
They are not resolved, normalized or interpreted as credentials. `siaddr`
is not equated with the DHCP server identifier option.

Option parsing distinguishes one-byte Pad (0) and End (255) from ordinary
code/length/data fragments. The primary options field is examined first.
Only a primary concatenated overload value 1, 2 or 3 activates `file`,
`sname` or both. Activated fields are visited in options, file, sname order,
not their physical packet order. Each activated fixed field must contain
its own End and remaining Pad bytes; a TLV cannot cross a field boundary.
Unselected header fields remain opaque.

Every repeated code is concatenated in that same order before supported
logical length checks. Zero-length fragments are retained, not discarded.
Each fragment has its field, absolute offset, code, length and exact data;
each logical option has its contributing fragment indices. Option overload
is never recursively activated by secondary fields. A primary empty overload
cannot establish which fields to inspect and stays unassessed. A secondary
nonempty overload contribution stays unassessed and cannot activate another
field. This is an explicit closed-profile limit, not a claim about all
possible agents' handling of an ambiguous packet.

The finite option subset interprets fixed lengths for requested address (50),
lease integer (51), overload (52), message type (53) and server identifier
(54). Client identifier (61) has only its minimum length checked and remains
opaque. Other option semantics are unassessed even when their TLVs are
complete. No host/URI resolution or extension option semantics are performed.
Lease `0xffffffff` is retained as an unsigned wire quantity; the algorithm
consults no clock and grants no lease use.

Declared DISCOVER/OFFER and REQUEST/ACK pairs have the RFC 2131 Table 3/5
subset checked: request/reply op, transaction ID, declared hardware tuple,
flags, `giaddr`, all sixteen copied `chaddr` bytes, reply zero hops/secs and
type-specific `ciaddr`. Client reserved flag bits are checked separately.
The selected response requires lease (51) and server identifier (54), and
must not contain requested address (50), parameter request list (55) or
maximum message size (57). Hardware type registry semantics, request client
state, selected server/address correlation, relay topology, actual binding,
pool availability and transport delivery remain outside the subset. An
offer need not echo a client's requested address; no such equality is invented.
No client-identifier echo obligation from later DHCP updates is inferred.

## Outcomes and replay

`supported_checks_outcome` is `consistent_supplied_subset`, `incomplete` or
`contradictions`. These refer only to supported byte/pair checks. Unknown
BOOTP vendor format, absent DHCP type, unsupported message pairs, unknown
option semantics and non-Pad primary data after End withhold a consistent
result. Primary truncated prefixes preserve earlier complete fragments but
do not interpret an incomplete logical aggregate as a complete message.
Impossible fixed-field crossings and selected copied-field contradictions
are static observations, not security or network conclusions.

All effects are fixed to `none`; source-authentication, complete-validity,
lease/address/server/delivery, vulnerability, live-use and qualification
flags are fixed false. No allocator, replay custody, consent, authority,
rogue-server judgment, exploit, renewal, IPAM or endpoint is produced.

The frozen wrapper stores owned canonical report text. Direct construction,
`from_dict`, `from_json`, `to_dict` and `to_json` fully rederive its embedded
source pair, not just the outer hash. Coherently readdressed false results
cannot pass that replay. Exports are detached. An alternate genuinely
consistent source can have its own valid report; only the separately supplied
original-model verifier establishes exact correlation with that original.
This still does not establish who supplied either model. No arbitrary Python
process isolation, concurrent-memory guarantee or external rollback is claimed.

## Software budgets

| Resource | Ceiling |
| --- | ---: |
| Each decoded packet | 8,192 bytes |
| Canonical model / report | 32,768 / 262,144 bytes |
| Model / report native nodes | 1,024 / 32,768 |
| Scalar-inclusive native/raw depth | 16 |
| Each packet's fragments / aggregate option data | 256 / 8,192 bytes |
| Observations | 256 |
| Native string | 16,384 printable ASCII characters |
| Cumulative work per public operation | 67,108,864 charged units |

These are local software-cost limits, not protocol maxima or measurements of
a client/server's performance. Simultaneous maxima need not fit every public
pass. Bounds apply to native repeated graphs, queued nodes and exact canonical
escaping before copying; bytes/depth/nodes/scalar lexical lengths/signed64
integers/string escapes before the raw JSON decoder; and decoded size before
base64 allocation. Duplicate keys, aliases, subclasses, floats, cycles and
non-ASCII metadata reject through `Dhcpv4AnalysisError`.

Fragment and logical-option bytes/work are charged before allocation and
retention. Complete report native sizes, fixed-width source/report identities,
future digest/serialization buffers, equality and detached-export work are
reserved before any own SHA256. All eight public operation paths use one
cumulative budget, including both derivations in separate-original verification.
Software exhaustion is a domain error, never a packet contradiction or retry.
Tests distinguish real default limits from transparently reduced exact-cost
boundaries and exercise genuine high-retention packets before hashing.
