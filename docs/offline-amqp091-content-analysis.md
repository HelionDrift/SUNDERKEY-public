# Supplied AMQP 0-9-1 Basic.Publish content assembly

This leaf analyzes one caller-supplied, post-negotiation sequence of AMQP 0-9-1 frame bytes. It does not connect to a broker, acquire packets, prove a connection, publish a message, verify permissions, or establish routing or delivery. The output is an unsigned content-addressed observation of supplied bytes and has no positive authority effect.

The existing specialist is `AOE-GB-D07-S07`, capability `army.gb.d07.s07`, vector `AV-GB-D07-S07-01`, package `IWP2-AOE-GB-D07-S07`, wave `IW2-007`, commander `AOE-GB-D07-CMD`, group reviewer `AOE-HQ-04`, independent validator `AOE-HQ-34`, and blueprint `sha256:c10fea2af225753591965ec2de3b8a55cf4d0ed37c1a6048a867022b6e1916e0`. This is partial A7.4 offline evidence only.

Primary source: the [AMQP 0-9-1 protocol specification](https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf), sections 2.3.5 and 4.2.3 through 4.2.6, and the [official XML definition of Basic.Publish](https://github.com/rabbitmq/amqp-0.9.1-spec/blob/main/xml/amqp0-9-1.xml). The spec describes a seven-octet frame header, an exact 0xCE frame terminator, content method followed by exactly one same-channel content header and body frames totaling its declared size, and permitted interleaving across different channels. `Basic.Publish` is class 60, method 40. This implementation is an independently written finite subset, not a protocol stack.

## Exact input and supported calculation

The closed source model has exactly four fields:

```json
{
  "schema_version": 1,
  "source_id": "synthetic-amqp-publish-content",
  "direction": "client_to_server",
  "frames_base64": "...canonical standard padded base64..."
}
```

`direction` is a caller assertion, not an observation. `frames_base64` is one complete, nonempty sequence of frame octets without the eight-octet protocol header or any TCP/transport framing. The original canonical base64 source remains embedded unchanged in the report. An arbitrary nonzero channel ID is parsed but never proven open or connected. Frame payloads and Basic.Publish short strings are retained as uppercase hex without turning exchange or routing-key bytes into trusted names.

The supported case is Basic.Publish method frames with bounded reserved-ticket and bit fields, a same-channel class-60 content header with weight zero and zero property flags, and body frames whose payload lengths exactly sum to the declared unsigned 64-bit size. A zero-length body completes at the header and needs no body frame. Body frames can be split, and separate channels may interleave without combining their content. Each publication retains frame indices, channel, raw method fields, declared body size, body bytes and `assembly_state`. The method's `mandatory` and `immediate` bits are decoded as declarations only. Nonzero unused bit positions withhold a clean conclusion because this subset does not assert how a receiver handles them. A nonzero reserved ticket, malformed UTF-8 short string or embedded zero octet is a supported contradiction. No exchange existence or routing decision is inferred.

Framing overrun, malformed Basic.Publish argument structure, a wrong frame-end octet, or a local software ceiling raises `Amqp091ContentAnalysisError` without returning a partial report. Unknown methods, frame types, nonzero property flags, and a supplied stream ending in pending content make the overall status `unassessed`, not clean. A same-channel method after partial body is recorded as an interruption without claiming broker behavior. Header/body frames without a supported pending method are a known contradiction only when the channel has no unsupported method or frame context; under an unsupported context they remain unassessed. A second header before body completion and a body exceeding the declared count are supported contradictions. Known contradictions dominate uncertainty in `analysis_status`, but that status concerns only these supplied declarations.

The report's status values are `consistent_with_supported_subset`, `unassessed`, and `contradicts_declared_subset`. Even the first status does not claim complete AMQP conformance, authenticated peer identity, a negotiated frame maximum, broker acceptance, queue permissions, message publication, persistence, delivery, or receipt. Content properties other than zero flags, other methods, heartbeats, connection/channel negotiation, publisher confirms, transactions, queue declarations, routing semantics and server responses are not interpreted.

## Replay and software bounds

Public APIs are `analyze_supplied_amqp091_content(model)`, keyword-only `analyze_supplied_amqp091_content_bytes(*, model_bytes)`, and `verify_supplied_amqp091_content_analysis(report, *, model)`. `Amqp091ContentAnalysis` offers validating direct construction, `from_dict`, `from_json`, `to_dict`, and `to_json`; `component_fixture()` returns a fresh hash-free two-channel synthetic model. All eight public forms reconstruct the full exact source-derived report, and the verifier also requires a separately supplied original source model. Re-exports are metadata only, not independent source verification. A coherently rehashed false assembly/status or source substitution fails replay.

The local software ceilings are 256 KiB source frame stream, 64 KiB per frame payload and per publication body, 512 KiB model, 1 MiB report, 128 frames, 16 observed nonzero channels, 64 Basic.Publish methods, 512 observations, depth 16, model nodes 512, report nodes 65,536, and 128 MiB cumulative work for one public operation. Maximum string and raw JSON intake limits also apply. Simultaneous maxima are not promised. The implementation checks exact native types, cycles, signed-64 integers, duplicate raw keys, malformed numbers and structural raw depth before decoding, then charges bounded frame parsing, retained output, model/report replay, equality and serialization before its first SHA operation. Complete records are built with fixed-width identity placeholders before the final addresses are calculated. A source body may contain arbitrary binary bytes; it is retained, not redacted.

Tests use independently encoded frames and header/body layouts. They cover cross-channel interleaving, same-channel sequence and interruption, zero/fragmented bodies, mismatch/overrun, unsupported method and property contexts, raw/native aliases, coherent false report/source replay and reduced work-ceiling denial before the first digest. These controls are local and synthetic; they are not broker or transport tests.
