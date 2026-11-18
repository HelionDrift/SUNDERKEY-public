# Supplied IPv4 fragment and checksum arithmetic

This partial offline algorithm reads caller-supplied inert IPv4 octets. It
observes header equations, fragment intervals and overlapping octet equality.
It does not acquire packets, send traffic, reconstruct a payload, simulate a
receiver or establish that the supplied packets belong to one real datagram.

The component is `ipv4_supplied_fragment_relations_and_header_checksums`. It
provides partial A7.4 evidence for the existing TCP/IP and IPv6 specialist:
`AOE-GC-D13-S01`, capability `army.gc.d13.s01`, vector `AV-GC-D13-S01-01`,
package `IWP2-AOE-GC-D13-S01`, wave `IW2-004`, commander `AOE-GC-D13-CMD`,
group commander `AOE-HQ-05` and independent validator `AOE-HQ-19`. Its blueprint
digest is
`sha256:566fbac84eb4d1b27b0c94dfd8cc04d5da90239b3b49645784ef54646c9bcdb6`.
The explicit component selector does not replace any existing default.

## Exact supplied model

The root has exactly three fields. Every list is nonempty and preserves the
original caller order; labels are bounded native ASCII strings. Set IDs and
packet IDs must be unique within the complete supplied model.

```json
{
  "schema_version": 1,
  "source_id": "synthetic-ipv4-fragments",
  "fragment_sets": [
    {
      "set_id": "declared-comparison",
      "packets": [
        {"packet_id": "first", "packet_base64": "..."},
        {"packet_id": "last", "packet_base64": "..."}
      ]
    }
  ]
}
```

Each packet uses canonical padded standard base64. The decoded bytes start at
IPv4 byte zero, without a link header. This closed software profile requires
version 4, IHL 5 through 15, the complete indicated header, a total length
exactly equal to the supplied bytes and a nonempty payload. Unsupported framing,
truncation, an empty payload or exhausted software budgets raises
`IPv4FragmentAnalysisError`. Such refusal is not a verdict about packet delivery
or a full IPv4 validity check.

```python
from sunderkey.offline_ipv4_fragment_analysis import (
    IPv4FragmentAnalysis,
    analyze_supplied_ipv4_fragments,
    analyze_supplied_ipv4_fragments_bytes,
    component_fixture,
    verify_supplied_ipv4_fragment_analysis,
)

original = component_fixture()  # Fresh literal synthetic bytes; no hash work.
report = analyze_supplied_ipv4_fragments(original)
document = report.to_dict()
canonical_report = report.to_json()
restored = IPv4FragmentAnalysis.from_json(canonical_report)
verified = verify_supplied_ipv4_fragment_analysis(restored, model=original)
```

The bytes API takes the keyword-only `model_bytes` containing bounded native
ASCII JSON. JSON spacing and key order are not source identity. The complete
native model, its list order, labels and exact canonical base64 are source-bound.
Duplicate raw JSON keys, fractional numbers, integer aliases, subclasses,
cycles, non-ASCII metadata and unbounded documents are refused. Report JSON must
be the exact canonical representation; `from_dict` canonicalizes a detached
native document before reconstructing it.

## Header observations

Network-order fixed fields, offset units, byte extents and the header checksum
are derived from the supplied octets. The checksum equation folds the complete
header, including the supplied checksum, to `0xffff`. A separate field reports
the canonical complement with the checksum field cleared. These are not the
same acceptance test: the equivalent one's-complement zero spellings can satisfy
the complete-header equation while differing from that canonical spelling.
Header checksum failure, a nonzero reserved header flag and nonterminal payload
length not divisible by eight remain explicit contradictions without changing
the original bytes. These relationships follow the header/fragment fields in
[RFC 791 sections 3.1 and 3.2](https://www.rfc-editor.org/rfc/rfc791.html#section-3.1)
and the checksum equation described in
[RFC 1071 section 1](https://www.rfc-editor.org/rfc/rfc1071.html#section-1).

Options are bounded by the supplied IHL. EOL, NOP and zero padding after EOL are
recognized. Other type/length/value options retain their exact hex octets,
length, class, number and copy bit, with semantics explicitly unassessed.
Missing or out-of-header lengths and nonzero EOL padding remain contradictions;
parsing stops rather than inventing the rest of a malformed option. Options,
IHL and TTL need not be equal across packets. The DS octet is opaque; the old
TOS reserved-bit interpretation is not applied. These are framing observations,
not option execution or complete protocol validation.

A received fragment with DF set is not universally marked invalid. Atomic
fields mean DF=1, MF=0 and offset=0; their identification values cannot bind
comparison groups or prove duplicate detection. The updated ID and received-DF
boundaries are specified in
[RFC 6864 sections 4.1 through 4.3](https://www.rfc-editor.org/rfc/rfc6864.html#section-4.1).
No endpoint identity, ID uniqueness or capture membership follows from a
checksum or an equal wire tuple.

## Separate literal and conditional axes

The report retains `packets`, `fragment_sets`, `contradictions` and
`unassessed_reasons` separately. Every supplied set has these literal results,
even when a single-datagram interpretation is withheld:

- Ordered packet-pair intervals, overlap lengths, equal/conflicting overlap
  octets and the first differing offset, plus exact whole-packet byte equality.
- Merged supplied intervals and union size, MF=0 endpoint values, and literal
  gaps/past-end intervals when there is one such endpoint.
- Equal/different source-address, destination-address, protocol and ID tuples,
  and whether any packet has atomic fields.

There is no reassembled payload in the report. Pair equality is mechanical
comparison of supplied octets, not a network-duplicate or receiver-behavior
claim. Sorting intervals for union arithmetic does not simulate arrival order;
the embedded source, packet rows and pair witnesses retain input order.

Only an equal, entirely non-atomic wire tuple permits the explicitly conditional
single-tuple conclusion. Under that hypothesis, inconsistent terminal extents,
payload past the sole terminal extent, a nonterminal reaching that endpoint or
an impossible original IPv4 extent are conditional contradictions. Missing
initial/terminal fragments and gaps are incomplete supplied evidence, not an
invalid real datagram. Atomic or mixed-tuple sets withhold that interpretation
while keeping their literal arithmetic. Known header contradictions remain
visible even when a group or option semantics is unassessed.

Overlapping octets never select discard, first-wins, last-wins, a filtering rule
or a vulnerability. IPv4 overlap support remains part of
[RFC 6864 section 4.2](https://www.rfc-editor.org/rfc/rfc6864.html#section-4.2).
[RFC 1858](https://www.rfc-editor.org/rfc/rfc1858.html) provides historical
filtering context, not rules implemented here.
[RFC 5722](https://www.rfc-editor.org/rfc/rfc5722.html) is IPv6-specific and is
not used to impose an IPv4 discard requirement.

## Exact replay and ownership

The frozen wrapper contains canonical `document_json`. Native analysis, bytes
analysis, direct construction, `from_dict`, `from_json`, `to_dict`, `to_json`
and separate-original verification each reconstruct the complete derived
document under a fresh cumulative budget. Coherently rehashing a false derived
row does not satisfy reconstruction. Separate-original verification funds and
rederives both the embedded and independently supplied model, and rejects
changed labels, bytes or list order. Exports and returned wrappers are detached;
an incomplete or foreign wrapper is not accepted as verified use.

The report addresses are `analysis_id` (`IPFA-`) and `analysis_sha256`.
`source_model_sha256` uses
`sunderkey.offline-ipv4-fragment-model.v1`; the report uses
`sunderkey.offline-ipv4-fragment-analysis.v1`. Packet hashes bind exact supplied
bytes. These unsigned content addresses establish reproducible software
identity, not source authenticity or authority. The embedded base64 is retained
unsanitized original source, not redacted or safe content.

## Finite software costs

| Structural cost | Ceiling per derived model or bounded document |
| --- | ---: |
| Sets / packets per set / aggregate packets | 16 / 64 / 128 |
| Packet bytes / aggregate decoded packet bytes | 65,535 / 524,288 |
| Canonical model bytes / complete report bytes | 1,048,576 / 2,097,152 |
| Native model nodes / report nodes | 4,096 / 262,144 |
| Scalar-inclusive native/raw depth | 16 |
| Decoded ASCII string length | 87,380 |
| Pair evaluations across all sets | 2,048 |
| Contradiction and uncertainty observations, combined | 2,048 |
| Compared overlap octets across all pairs | 8,388,608 |
| Cumulative software work units | 134,217,728 per complete public operation |

Packet, set, pair, observation and compared-overlap counters describe one
derived model. Model/report byte and node ceilings bound each respective
document, not the sum of all supplied objects. Separate-original verification
derives two models without changing those report facts. It uses one work
budget for both complete plans, raw/native intake and their final equality;
its counters are not shared structural counters across the two plans.

Raw byte, string, signed64 lexical, scalar-depth and node costs are checked
before JSON decoding. Packet counts and decoded byte lengths are checked
before base64 decoding. Pair and overlap budgets are checked before comparison;
retained rows are checked before append. Row retention conservatively charges
nested rows again when retaining their parent, so a refusal can precede the
final encoded-report ceiling. The complete report, fixed-width address fields,
canonical encodings, hashes, clones and equality work are reserved before the
first SHA operation. Separate-original verification reserves both complete
plans and their comparison first. No additional cost is charged after hashing
starts. Export uses its own fresh replay budget and is not free hidden work.

These are local software-cost limits, not protocol authority or a promise that
all maxima fit together or that every public form accepts a model at every
individual maximum. The report grants no capture, network, target,
provider, credential, process, execution, routing, qualification, deployment or
publication effect. All authentication, one-datagram, receiver, delivery,
transport, vulnerability, full-validity and live-use claims remain false.
