# Offline supplied DKIM canonicalization

This partial component computes canonical bytes and hash arithmetic from a
caller-supplied message. It does not verify a DKIM signature, acquire a DNS key,
authenticate a domain, decide mail acceptance, or assess SPF or DMARC. All
operational effects are `none` and all authority and qualification flags are
false. A matching supplied body hash is not a verified signature.

## Existing ownership

The component ID is `dkim_supplied_canonicalization_and_body_hash`. Its existing
registered profile is `AOE-GC-D13-S14`, capability `army.gc.d13.s14`, vector
`AV-GC-D13-S14-01`, package `IWP2-AOE-GC-D13-S14`, and wave `IW2-017`. The commander
is `AOE-GC-D13-CMD`, group owner `AOE-HQ-05`, and independent validator
`AOE-HQ-19`. The exact blueprint binding is
`sha256:6ede9269d562acfd25fa6e2c0dc197ad9fc5b4b450d03fb2f5f3e1c768803e3a`.
Only partial supplied-data evidence for A7.4 is established. No package state,
routing, deployment, live-use gate, existing SDK, or qualification is changed.

## Closed input and public APIs

The model has exactly these native fields:

```json
{"schema_version":1,"source_id":"synthetic-dkim-arithmetic","message_base64":"...","dkim_header_index":0}
```

`message_base64` is the complete canonical padded base64 encoding of the supplied
message bytes. `dkim_header_index` is the zero-based physical header field index
from the top of the message, not a physical line or signing-order assertion. It
must identify a `DKIM-Signature` field. `source_id` is a caller label of at most
64 ASCII identifier characters, not authenticated mailbox evidence.

- `analyze_supplied_dkim_canonicalization(model)` returns an owned
  `DkimCanonicalizationAnalysis`.
- `analyze_supplied_dkim_canonicalization_bytes(*, model_bytes)` accepts exact
  native bytes containing bounded duplicate-free ASCII JSON. The JSON spelling
  is decoded to the closed model; exact message bytes remain separately retained.
- `verify_supplied_dkim_canonicalization_analysis(report, *, model)` rederives
  the embedded and separately supplied original models and compares complete
  canonical reports, not only their source or report digests.
- The wrapper constructor, `from_dict`, `from_json`, `to_dict`, and `to_json`
  replay the complete embedded original message. Report JSON must have the exact
  canonical spelling. Exports are detached, and forged or late-mutated native
  wrappers cannot export a misleading report.
- `component_fixture()` returns a fresh, wholly synthetic public-only model.
  Its inert `b=AQ==` declaration is not an actual RSA signature.

The wrapper contains the complete original message base64, canonical body, and
header preimage. It is **not sanitized for publication**. Supplied messages may
contain confidential content, identifiers, or signature values. The library
does not acquire or transmit messages and adds no publication mechanism.

## Supported arithmetic

The finite profile follows the canonicalization and input-to-hash rules in
[RFC6376 sections 3.2, 3.4, 3.5, 3.7, and 5.4.2](https://www.rfc-editor.org/rfc/rfc6376.html).
It supports declared version `1`, algorithm token `rsa-sha256`, and `simple` or
`relaxed` header/body combinations. Missing `c` means `simple/simple`; a single
mode means that header mode and a `simple` body. This is a software arithmetic
subset, not a current cryptographic policy recommendation or full verifier.

Intake requires the first CRLFCRLF header/body separator, paired CRLF throughout,
bounded ASCII header field names and values, and legal SP/HTAB continuations.
Optional SP/HTAB before a header colon is explicitly accepted in this declared
arithmetic subset: `simple` preserves it and `relaxed` removes it with the other
prescribed boundary whitespace. No wider RFC5322 or SMTP validity is asserted.
The body remains opaque octets; no MIME decoding, Unicode normalization, SMTP
dot-unstuffing, or guessed end-of-message processing occurs. Only SP and HTAB
count as canonicalization whitespace. A nonempty body lacking a final CRLF is
canonicalized without claiming that such bytes were transmitted.

`simple` headers retain exact spelling and folds. `relaxed` lowercases the field
name, unfolds continuation CRLF, collapses SP/HTAB runs, and removes the
prescribed value and colon-boundary whitespace. Simple bodies retain nonempty
and whitespace-only lines, remove trailing empty lines, and use CRLF for an
empty body. Relaxed bodies strip trailing SP/HTAB from each line, collapse those
runs, and remove resulting trailing empty lines; an empty body has zero bytes.

Tags retain case-sensitive names, source order, and original byte spans.
Required `v`, `a`, `b`, `bh`, `d`, `h`, and `s` declarations must exist in the
selected field. Duplicate tags or malformed supported tag grammar cause a
`DkimCanonicalizationError`. Unknown tags, including empty or case-distinct
names, remain in the preimage. Domain and selector values are nonempty opaque
declarations, not validated DNS names. Identity, query, timestamp, expiry, and
copied-header tag semantics are unassessed.

The `h` list selects the bottom-most unused matching physical field for each
case-insensitive name in supplied order. An absent selection contributes zero
bytes, including no name, colon, or CRLF. The selected signature itself is
excluded from that selection; other selected DKIM fields retain their own `b`
values and are not separately validated as signatures. Each selected ordinary
field has its CRLF contribution. The selected signature is appended last after
removing exactly its original `b` value span and surrounding FWS, leaving the
tag name, equals sign, delimiters, other tags, and original `bh` intact. Its final
CRLF is excluded. No tag-dictionary reconstruction occurs.

The body is canonicalized before applying `l`. Missing `l` covers all bytes;
zero, exact, and partial prefixes are observed without any acceptance claim.
The original one-to-76-digit decimal spelling is retained, with lexical length
comparison before bounded integer conversion. An oversized `l` is a declared
coverage contradiction: the covered hash and comparison are null, never
clamped. Supported `bh` base64 ignores only FWS and must decode to 32 bytes.
The mathematical comparison uses those decoded bytes, retaining original header
spelling in the preimage. The SHA256 preimage digest is a byte fingerprint, not
a public-key signature result or Authenticated Received Chain result.

Well-shaped unsupported version, algorithm, or canonicalization declarations
produce `arithmetic_unassessed`, explicit reasons, and null unavailable fields.
An unsupported algorithm's `bh` is not forced into the 32-byte SHA256 profile.
Known body-hash mismatch is a fully computed false observation, not a DKIM
`PERMFAIL`, mail-rejection, identity, or domain conclusion. Likewise,
`arithmetic_computed` does not mean full mail, signature, signed-From, expiry, or
cryptographic-policy conformance.

## Software ceilings and replay costs

The message ceiling is 256KiB, headers including their separator 64KiB, each
physical line content 8192 bytes, 512 physical fields and `h` selections, 64
selected tags, and 32768 physical body lines. Model canonical JSON is bounded to
512KiB because message base64 expands the 256KiB source. Report JSON is at most
1MiB. Native model/report ceilings are 4096/65536 visited nodes and depth16,
including scalars. Native JSON integers fit signed64, while `l` is separately
bounded textual decimal metadata. Exact native families exclude subclasses,
bool/int and float/int aliases in typed positions, cycles, and open shapes.

Raw JSON has byte, scalar-inclusive depth, node, printable-string/escape, and
integer-grammar checks before decoder allocation. Native source/report capture
checks bounds and typed shapes before ownership copying. Physical byte/line
counts precede line collection. Retained rows and bulk base64 output are funded
before allocation or append. Complete canonical body and header preimage are
bounded by message-plus-two and supplied-header extents respectively.

Every public operation has one cumulative 64MiB work counter covering capture,
raw copy/scan/decoder work, base64, canonicalization, retained observations,
replays, equality, final encoding, and digest buffers. Complete remaining costs
are conservatively reserved before **any** SHA256 call, including the body and
preimage content digests. Worst-case fixed-shape comparison, violation, and
status widths are reserved before the hash-dependent comparison is known.
Content arithmetic digests precede final model/report addressing, but no fresh
budget is introduced between those stages. The separate-original verifier funds
both plans before either plan hashes. These are software work units, not timing
or process-memory isolation guarantees; simultaneous maxima need not fit a
complete replay or final report cap.

Model and report domains are distinct. `source_message_sha256` fingerprints the
exact entire supplied message, not authenticated mail or sender provenance.
Original JSON field order does not create authority. A caller may construct a
new truthful report for changed supplied bytes, but it cannot replay against a
different separately supplied original model.

## Independent fixture and negative controls

The finite tests use a separate line-table oracle and header-selection stack
oracle, independently assembled preimages, repeated/absent header selections,
unknown tags and other-signature preservation, before-colon whitespace, `l`
boundaries, and the literal empty-body SHA256 vectors from RFC6376. Controls also
exercise unsupported versus malformed declarations, real byte/count ceilings,
duplicate/raw/native families, source substitution, coherent false readdressing,
late wrapper mutation, fresh detached exports, and exact work thresholds at all
eight public paths before the first digest. No operational messages, keys,
mailboxes, network ports, or target resources are used.

The public synthetic fixture yields
`DCA-F58B5A06975C4D52D03EF747BA432A59`, report digest
`sha256:f58b5a06975c4d52d03ef747ba432a592bdb38366c402a87e8aac89dbc034e9d`,
model digest
`sha256:444274ae769e57d41a7a0c92044636b5f60fe970031046e7300a3cb4761571da`,
and exact message digest
`sha256:bea01854c5d658f9a90bfbd2d3f2bdbf1e5dde8c13a2dfeb6e8dc6c80d59833a`.
It has 232 source bytes, an empty relaxed body whose supplied hash matches, and
218 preimage bytes. The physical selections are `[1,3,2,null]`; the final absent
selection contributes zero bytes. These are unsigned arithmetic goldens only.
