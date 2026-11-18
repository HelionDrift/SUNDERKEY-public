# Supplied MQTT 3.1.1 topic/filter arithmetic

This partial offline specialist component evaluates supplied topic names,
subscription filters and explicit query pairs. It uses no broker, network,
provider, credential, process, session, message delivery or qualification port.
It is not a completed or qualified specialist and is not an access-control test.

## Existing ownership

The component is `mqtt_supplied_topic_filter_arithmetic`, owned by
`AOE-GD-D18-S15`, capability `army.gd.d18.s15`, vector `AV-GD-D18-S15-01`,
work package `IWP2-AOE-GD-D18-S15` and existing wave `IW2-019`.
The commander is `AOE-GD-D18-CMD`, group commander `AOE-HQ-06` and independent
validator `AOE-HQ-33`. The blueprint is
`sha256:a3e9ff84eaf62017510d6009eb674c0e8790538e96ad8a9bd86a99b0c4c9af3b`.
Initial evidence is partial A7.4 software evidence only. No wave, package,
qualification, routing, target authority or deployment status is promoted.

## Public API and closed source

`analyze_supplied_mqtt_topics(model)` accepts this exact native JSON shape:

```json
{
  "schema_version": 1,
  "protocol_version": "3.1.1",
  "filters": [{"filter_id": "branch", "topic_filter": "sensors/#"}],
  "topics": [{"topic_id": "parent", "topic_name": "sensors"}],
  "match_queries": [
    {"query_id": "match-parent", "filter_id": "branch", "topic_id": "parent"}
  ],
  "overlap_queries": [
    {"query_id": "overlap-self", "left_filter_id": "branch", "right_filter_id": "branch"}
  ]
}
```

Source IDs are bounded ASCII identifiers, unique within their source family.
Query IDs are unique across both query families. Every reference must resolve
exactly. Duplicate source text under distinct IDs is allowed. Empty source and
query arrays are allowed and produce no invented assessment. Extra fields,
unsupported protocol versions, native scalar aliases and malformed strings
are rejected with `MqttTopicAnalysisError`.

The byte API is
`analyze_supplied_mqtt_topics_bytes(*, model_bytes)`. It accepts exact native
bounded UTF-8 bytes, rejects duplicate JSON keys at every level and preserves
the parsed source projection. Whitespace and equivalent JSON Unicode escapes
may differ at intake without changing that projection's identity. Its source
digest does not authenticate origin or bind the original raw JSON bytes.

`component_fixture()` returns a fresh public inert model directly. It includes
an empty topic level, a parent matched by a terminal hash, a dollar-root
exclusion and an exact Unicode spelling. It contains no acquired broker facts.

## Supported mathematical semantics

The implementation is independently written against the official
[OASIS MQTT 3.1.1 specification](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html),
sections 1.5.3 and 4.7. It does not copy upstream parser or matching code.

- `+` occupies a whole level and consumes exactly one level, including empty.
- Terminal `#` occupies a whole level and consumes zero or more descendants.
  Consequently `a/#` includes `a` and `a/`.
- A filter starting with `+` or `#` cannot match a topic starting with `$`.
  A dollar in any later level has no such root exception.
- Leading, trailing and adjacent separators remain significant. `/` is valid;
  an entirely empty topic or filter is not.
- Case and exact Unicode spelling are retained without normalization.
  U+FEFF is literal data, not a marker to strip.
- Topic names cannot contain `+` or `#`. Wildcard characters in filters must
  have the specified complete-level positions.
- NUL, surrogate codepoints and ill-formed UTF-8 are rejected. Controls and
  Unicode noncharacters have SHOULD-level protocol cautions. Their presence
  is recorded, not universally labelled invalid.

MQTT 5 shared subscriptions are not interpreted. Text such as
`$share/workers/a/#` is an ordinary supplied MQTT 3.1.1 filter here, not a
subscription to `a/#`. No QoS, retained-message, broker session or delivery
behavior follows from any match result.

## Symbolic overlap and witness limits

Explicit overlap pairs use aligned level constraints. A literal conflicts
only with a different literal; `+` and the repeated terminal `#` have free
level constraints. The algorithm accounts for fixed lengths, the dollar-root
exception and the prohibition on an empty Topic Name. It chooses a shortest
legal level count and smallest UTF-8 width by using empty unconstrained levels,
or one ASCII character when a single otherwise-empty level needs a name.

An `overlap_witness` row includes a concrete topic. Before retaining it, the
implementation checks its software byte/level bounds and independently passes
it through both mathematical matchers. A `disjoint` row means the supplied
filter languages have a literal, length or root-dollar contradiction.

`no_witness_within_software_topic_bounds` is separate from disjointness. For
example, each of two individually bounded filters can force a combined topic
over the 4096-byte software ceiling. The report retains the minimum witness
byte requirement but no oversized topic. It never calls that pair disjoint.
These results are pattern mathematics, not broker authorization or safety.

## Replay, ownership and costs

`MqttTopicAnalysis` is a frozen wrapper owning canonical ASCII-escaped report
JSON. `from_dict`, `from_json`, direct construction, `to_dict` and `to_json`
rederive every result from the complete embedded model. Report JSON must be
exact canonical JSON. Rehashing false results, substituted sources, promoted
effects or native aliases does not bypass semantic replay.

`verify_supplied_mqtt_topic_analysis(report, *, model)` additionally derives
the report from the separately supplied original model. Embedded replay alone
cannot establish that an alternate valid source is the caller's original.
Returned dictionaries and public fixtures are detached. The checks do not
authenticate records, contain arbitrary Python code or guarantee consistency
against concurrent caller memory mutation or valid pre-entry replacement.

The ceilings are simultaneous software limits, not MQTT protocol maxima:

| Limit | Ceiling |
| --- | ---: |
| Model / report canonical escaped bytes | 256 KiB / 1 MiB |
| Model / report native nodes | 16,384 / 12,288 |
| Native and raw value depth | 16 |
| UTF-8 bytes per string / topic or filter levels | 4,096 / 64 |
| Declared filters / topics | 128 / 128 |
| Explicit match / overlap queries | 512 / 256 |
| Cumulative work per public operation | 33,554,432 units |

Native shapes, cycles, repeated occurrences, UTF-8 and escaped-output costs
are checked before copying or serialization. Raw node/depth/string and signed
64-bit scalar lexical ceilings are checked before JSON decoding or integer
conversion. Compilation, comparisons, sorting, witnesses and aggregate retained
rows consume a cumulative budget. Every required source/replay/output/hash/
serialization/equality pass is reserved before the first address digest.
Output or work exhaustion raises a domain error, not a fabricated match result.
Maximum combinations need not fit the complete retained report or a multi-pass
verification operation. The full MQTT string limit is 65,535 bytes; this leaf
transparently chooses a narrower software subset.

## Synthetic validation boundary

The focused tests use a separately written recursive matcher and finite
alphabet enumeration for both matching and overlap. They cover empty levels,
zero-descendant hashes, dollar roots, exact Unicode, supplementary escapes,
software-only witness limits, malformed/native/raw intake, aggregate retained
costs, source replay, false cohashed results, ordering and detachment.

These are local synthetic software checks only. No broker installation,
traffic, credentials, authoritative capture, independent human qualification
or live target behavior is tested or claimed. All operational effects remain
`none`, and all provider/authorization/qualification claims remain false.
