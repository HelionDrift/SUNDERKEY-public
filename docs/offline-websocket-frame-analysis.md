# Supplied WebSocket frame-state analysis

`sunderkey.offline_websocket_frame_analysis` passively analyzes one supplied
sender's inert RFC 6455 frame prefix. It is a parser and incremental state
algorithm, not a connection, frame sender, endpoint probe or credential tool.
Only the Python standard library is used.

## Existing ownership

The partial component `websocket_supplied_frame_state` belongs to existing
profile `AOE-GB-D06-S05`, capability `army.gb.d06.s05`, vector
`AV-GB-D06-S05-01`, package `IWP2-AOE-GB-D06-S05` and wave `IW2-012`.
Its commander is `AOE-GB-D06-CMD`, group commander `AOE-HQ-04` and independent
validator `AOE-HQ-34`. The existing blueprint digest is
`sha256:e79163c291078b1fc158f18b9563eb6a1abe2500b7c25fb1d96aa1d996e50920`.
This is neither complete realtime API coverage nor specialist completion. It
does not alter the six reference candidates, owner decisions, assignments,
live-host gates, routing, deployment or qualification.

## Exact input and API

`analyze_supplied_websocket_frames(model)` accepts exactly this native model:

```json
{
  "schema_version": 1,
  "semantics_profile": "rfc6455-unextended-message-boundary-prefix-v1",
  "source_id": "synthetic:websocket-hello",
  "sender_role": "server",
  "initial_state": "message_boundary",
  "stream_base64": "gQVIZWxsbw=="
}
```

The fixture's literal bytes are `81 05 48 65 6c 6c 6f`. `sender_role` must be
`client` or `server`. `source_id` is a printable ASCII identifier of at most
128 characters, using letters, digits, dot, underscore, colon or hyphen.
`initial_state` and `semantics_profile` have only the shown supported values.
The message boundary, sender role and unextended post-handshake framing are
explicit caller premises, not observations of a negotiated connection.

`parse_supplied_websocket_frame_model(model_bytes)` accepts bounded native
ASCII JSON bytes only. It accesses no path or URL. Raw JSON representation
whitespace does not change the canonical model identity. Native base64 must
decode and re-encode exactly, including padding. Empty bytes are an incomplete
prefix with no supplied frame, not an invented complete session.

`WebSocketFrameAnalysis` exposes `to_dict`, `to_json`, `from_dict` and
`from_json`. Its constructor and every public read replay the full embedded
source model. `verify_supplied_websocket_frame_analysis(report, model=model)`
also compares the entire result against a separately supplied original model.
A coherent different source can produce a different legitimate report, but
cannot substitute for the original source in that verification.

## Supported structural algorithm

Headers are parsed with minimal length encoding, the 64-bit length high-bit
restriction and sender-specific masking. Text validation is incremental across
fragments; control frames can occur between them. Control FIN and 125-byte
limits, fragment ordering and data after sender Close are checked. Close
payload length, known forbidden codes and reason UTF-8 are observed.
[RFC 6455 framing](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.2),
[fragmentation and control](https://www.rfc-editor.org/rfc/rfc6455.html#section-5.4),
[Close codes](https://www.rfc-editor.org/rfc/rfc6455.html#section-7.4),
[UTF-8](https://www.rfc-editor.org/rfc/rfc6455.html#section-8.1)

The defined codes 1000, 1001, 1002, 1003 and 1007 through 1011 are distinguished
from forbidden 1004, 1005, 1006 and 1015. Other codes within 1000 through 4999
remain semantically unassessed; no later registry or private agreement is
inferred. Recognition of a known code does not establish that its use or reason
is appropriate. In particular, 1010 describes client initiation and 1011 a
server reason, but a Close echo requires unavailable peer context. A single
sender prefix cannot distinguish role-specific initiation from an echo, so
neither is certified and no universal role violation is invented. Mask-key
presence does not prove key randomness.

RSV bits and reserved opcodes stop payload interpretation. Their bytes are
not relabelled as valid text or decompressed. The known supported prefix is
retained, but later state is not guessed. Truncated headers, keys, payloads
and unfinished messages are incomplete supplied evidence. An unfinished
message interrupted by Close does not create an obligation to continue it.

`frames` contains half-open offsets, flags, lengths and hashes; `messages`
contains fragment counts, exact concatenated-payload hashes, completion and
UTF-8 status. No decoded application content or Close reason is displayed.
The original inert source model is embedded as base64. This is not secret
redaction, content classification or permission to publish sensitive inputs.

`observations` distinguishes `violation`, `incomplete` and `unsupported`.
`analysis_status` is `consistent_with_supported_subset`,
`structural_violation`, `incomplete_supplied_prefix` or `unsupported`.
Unsupported has precedence, but all already observed contradictions remain
in the result. `summary.supported_checks_complete` describes only this
software subset, not a valid connection or application. A software-cost
failure raises `WebSocketFrameAnalysisError`; it is not a frame contradiction.

## Software bounds and replay

Fixed ceilings are 1 MiB per supplied native/raw document and returned report,
256 KiB decoded stream, 128 KiB frame payload, 256 KiB message payload,
2048 frames, 1024 messages, 256 observations, native depth 16 (root depth 1)
and 32,768 visited native nodes. Repeated shared subtrees count repeatedly;
cycles, aliases, subclasses, floats and oversized integers are rejected.
Strings, escaping, punctuation and queued nodes are charged before native
detachment or serialization. Raw keys, values, scalar depth and bounded
signed64 numeric grammar are checked before JSON decoding. Duplicate keys
are rejected. Base64 size is bounded before decoding. Declared frame lengths
are bounded before payload allocation, even when the supplied payload is short.

Each parser reconstruction permits one million charged work units across
header/state steps, payload copies, unmasking, wire/decoded-payload hashes,
incremental message hashing and UTF-8 passes. Source/document serialization
and hashes have their separate native byte/node ceilings, not this parser
counter. Every public wrapper replay is a bounded reconstruction; the counter
is not a total across all reads of a report. Frame/message rows reserve their
worst-case metadata size before payload hashing. A fixed 512-byte and 64-node
reservation covers final identity/counter overhead. Observations and all final
documents are bounded before source/result hashing. Individual maxima are
upper bounds, not a promise every combination fits aggregate costs.

There is no repeated whole-message concatenation or expansion from a declared
length. Text decoding discards each bounded returned chunk immediately;
only decoder state and an incremental digest persist between fragments.
Coherently readdressed false offsets, counts, formulas, flags or observations
fail exact original-source replay, not only an address check.

## Explicit exclusions

No handshake, HTTP Upgrade, Origin, session authentication, authorization,
endpoint identity, compression, subprotocol, application payload semantics,
reconnect, timeouts, ping-response pairing or peer closing-handshake conclusion
is provided. No callbacks, sockets, file access, processes, providers,
operational credentials or traffic generation are accepted. No live clock,
source acquisition, action admission or consumption exists.

All reports are unsigned and nonqualifying. `server_vulnerability_proven`,
`live_use_approved` and `qualification_claimed` remain exact `false`; authority,
target, execution, routing, qualification, deployment and provider effects
remain `none`. The model and its fingerprints do not authenticate provenance.
