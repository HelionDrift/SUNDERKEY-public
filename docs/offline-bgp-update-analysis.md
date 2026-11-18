# Supplied BGP UPDATE structure, offline

This leaf observes exactly one caller-supplied BGP-4 UPDATE frame. It does not open a socket, acquire a capture, identify a peer, or select a route. Its evidence is an unsigned content-addressed description of supplied bytes, not a BGP acceptance decision or specialist qualification.

The existing owner is `AOE-GC-D13-S02` (BGP and OSPF), capability `army.gc.d13.s02`, vector `AV-GC-D13-S02-01`, package `IWP2-AOE-GC-D13-S02`, wave `IW2-005`, commander `AOE-GC-D13-CMD`, group reviewer `AOE-HQ-05`, validator `AOE-HQ-19`, and blueprint `sha256:ebdc526850dd9d8cd5b2cf3d7242cac1901b88e4d32d5af51f6200f218b0f02c`. This is partial A7.4 offline evidence only. It does not advance the scheduled, unassigned package.

Primary semantics: [RFC 4271, sections 4.1, 4.3, 5, and 6.3](https://www.rfc-editor.org/rfc/rfc4271.html) and [RFC 6793, section 4](https://www.rfc-editor.org/rfc/rfc6793.html). The model intentionally does not reconstruct `AS4_PATH` or infer the four-octet capability negotiation that can affect AS_PATH interpretation.

## Exact supplied model

The outer source document is an exact native dictionary with four keys:

```json
{
  "schema_version": 1,
  "source_id": "synthetic-bgp-update",
  "asn_width_octets": 2,
  "update_base64": "...canonical standard padded base64..."
}
```

`asn_width_octets` is exactly native integer `2` or `4`. It is a caller-declared interpretation premise, not proof of an OPEN exchange. `update_base64` decodes to one complete UPDATE, 23 through 4096 octets, starting with its 19-octet BGP header. Extra bytes and concatenated frames are refused. The base64 must re-encode exactly. `source_id` is a bounded ASCII label, not a peer or capture identity. The source model is embedded in the report unchanged after native detachment.

Public entry points are `analyze_supplied_bgp_update(model)`, `analyze_supplied_bgp_update_bytes(*, model_bytes)`, and `verify_supplied_bgp_update_analysis(report, *, model)`. `BgpUpdateAnalysis` has complete validating `from_dict`, `from_json`, `to_dict`, `to_json`, and direct-constructor paths. `component_fixture()` returns a fresh synthetic, hash-free 45-octet UPDATE. All eight public paths replay the entire source-derived report; an export alone is not independent source verification. The verifier also requires a separately supplied original model, rederives both models under one cumulative work budget, and refuses a changed source or coherently readdressed false conclusion.

## Supported observations

The finite subset checks the header marker, exact declared length, UPDATE type, withdrawn length and prefix encoding, attribute section and TLV lengths, and final IPv4-unicast NLRI section. It retains ordered raw prefix and attribute octets. For prefix equality it masks insignificant final-octet bits; nonzero fill bits remain visible but are not a contradiction. It recognizes ORIGIN, AS_PATH under the supplied 2/4-octet width, and the four-octet NEXT_HOP field. When NLRI is present, the three mandatory attributes must be present. A withdrawal-only UPDATE requires no attributes, and a correctly formed attribute section with no NLRI is not rejected. A repeated attribute type is a contradiction. Received low attribute-flag bits are retained and ignored, as required by RFC 4271. A canonical prefix present in both withdrawal and announcement lists is an advisory, not a refusal.

The report has separately ordered `withdrawn_prefixes`, `path_attributes`, and `announced_prefixes`, plus `known_contradictions`, `unassessed_reasons`, and `advisories`. `analysis_status` is `contradicts_declared_subset` when a known contradiction exists, otherwise `unassessed` when unsupported semantics are present, otherwise `consistent_with_supported_subset`. The last status is deliberately narrower than full BGP validity. Impossible framing or an overrun that prevents bounded parsing raises `BgpUpdateAnalysisError` rather than producing a partial success report. Unknown attribute values and AS4 reconstruction are unassessed, not declared clean. ASN-width choice is never independently authenticated.

NEXT_HOP host-address and reachability semantics beyond its four-octet shape, local and remote speaker addresses, RPKI origin validation, BGP policy, route preference, installed routes, AS loop decisions, topology, the OSPF half of the profile, and receiver notification behavior are outside scope. The report never executes a network or provider action. Its `effects` are all `none`; promotion and security claims are all false.

## Software costs and replay

One supplied frame is at most 4096 octets. The local profile also limits a model to 16 KiB, report to 256 KiB, depth to 16, model nodes to 512, report nodes to 16,384, attributes to 128, prefixes to 512 total, AS segments to 128, AS numbers to 512, and retained observations to 512. One complete public operation has a 32 MiB cumulative work ceiling. These are software cost limits, not BGP authority or a promise that all maxima can fit simultaneously. Structural ceilings apply to each derived model/report, while the separately-original verifier charges both derivations to one work budget.

Exact native JSON types, signed-64-bit integers, duplicate raw JSON keys, malformed scalar lexicals, excessive raw strings, depth and nodes are rejected before JSON decoding or report hashing. The frame is decoded and parsed, a complete report is built with fixed-width identity placeholders, and conservative serialization, replay, equality, clone, and digest work is reserved before the first SHA operation. No resource-ceiling discovery occurs after that first digest. The report retains the original base64 bytes; it is neither sanitized nor redacted. Canonical model identity does not claim to preserve the whitespace or key order of raw input JSON.

The synthetic checks use an independent byte encoder for frame lengths, prefixes, path attributes and 2/4-octet AS_PATHs. Negative cases cover truncation, duplicate attributes, missing mandatory attributes, ignored low flag and prefix-fill bits, the permitted cross-list same prefix, unsupported attributes, source substitution, native aliases, raw decoder bounds, detached exports and coherently rehashed false report fields. Fixed-point work checks exercise all eight public paths at a successful threshold and at one unit less, where refusal must precede the first digest.
