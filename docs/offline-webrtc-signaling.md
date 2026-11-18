# Supplied WebRTC signaling projection

This R0 component belongs to profile `AOE-GB-D05-S18`, capability
`army.gb.d05.s18`, vector `AV-GB-D05-S18-01`, package
`IWP2-AOE-GB-D05-S18`, and wave `IW2-018`. Its component ID is
`browser_supplied_webrtc_signaling_projection`. It contributes partial
offline evidence only and does not complete or qualify the specialist.

The schema version 1 model supplies a complete or incomplete room inventory.
Each room declares an exact sorted member list, whether membership and
forwarding policy are complete, and two explicit policy requirements:
`member_only_forwarding_required` and `sender_owner_match_required`. A false
rule means that the corresponding mismatch is not a contradiction. Each event
declares its room, sender,
recipient, payload owner, forwarding decision, direct-submission premise,
identity-binding completeness, and context completeness. The event kind is
`offer`, `answer`, or `ice_candidate`. These are envelope labels, not parsed
SDP or ICE content. Peer identifiers and room identifiers are bounded ASCII
tokens, not URLs or network destinations.

A candidate requires all completeness premises, direct peer submission,
concrete identities, and a declared `allow` forwarding decision. An outside
sender or recipient is a candidate only when `member_only_forwarding_required`
is true. A payload owner different from its direct sender is a candidate only
when `sender_owner_match_required` is true. A declared `deny` decision yields
`declared_forwarding_denied`, not an observed non-delivery claim or candidate.
Relay or server submission, unknown forwarding,
unknown identities, or incomplete declarations produce `unknown`. A candidate
is a contradiction within the caller's declarations. It is not proof that
signaling was delivered or that another peer or browser accepted it.

`analyze_supplied_webrtc_signaling` accepts a native model;
`analyze_supplied_webrtc_signaling_bytes` accepts bounded ASCII JSON bytes.
`verify_supplied_webrtc_signaling_analysis` rederives a report against a
separately supplied original model. `from_json` validates internal replay
from embedded source only, not the provenance of that source. The report
contains the source model, domain-separated source and report addresses,
bounds, limitations, false verification flags, and `none` effects. A
synthetic request is in `examples/offline-webrtc-signaling-component.json`.

This component does not parse SDP, ICE candidates, media, STUN, TURN, DTLS,
or browser protocol behavior. It does not open a browser, start a peer
connection, transmit signaling, execute payloads, or contact a URL, target,
network, process, provider, or credential source. It establishes no live
finding, authority, qualification, or positive-use approval.
