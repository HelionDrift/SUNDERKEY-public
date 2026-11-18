# Supplied HTTP request-framing analysis

`sunderkey.offline_http_request_framing` implements a finite passive parser for
one supplied HTTP/1.1 request prefix. It sends nothing, generates no traffic,
and does not predict how a server, proxy or second parser would interpret the
bytes. It uses only the standard library and installs no dependencies.

## Ownership and inputs

The existing specialist is `AOE-GB-D05-S03`, capability `army.gb.d05.s03`,
vector `AV-GB-D05-S03-01` and package `IWP2-AOE-GB-D05-S03`, scheduled in
`IW2-003`. Command ownership is `AOE-GB-D05-CMD`, group commander
`AOE-HQ-04` and independent validator `AOE-HQ-34`. This partial component
does not change package assignment, original D016 records, the six reference
SDKs, containment requirements, qualification, routing or deployment gates.

`analyze_supplied_http_request_framing(model)` accepts only this exact native
shape, with canonical base64 for the complete supplied octet string:

```json
{
  "schema_version": 1,
  "request_base64": "R0VUIC8gSFRUUC8xLjENCkhvc3Q6IGV4YW1wbGUudGVzdA0KDQo="
}
```

The example is a supplied benign `GET /` with an inert `example.test` Host.
The component accepts no transport, credential resolver, live clock, process,
network or provider callback. Supplied data should be inert or sanitized before
it reaches this API; its fingerprints are not automatically certified safe to
publish. No target, header value or body is emitted in the result.

## Finite parser behavior

The parser records exact half-open byte ranges. A line's end excludes its CRLF;
the header end and body end include their closing framing bytes. It checks the
request line, origin-form subset, field tokens, colon placement, control octets,
one nonempty Host field, declared lengths, transfer-coding order and chunk
boundaries. Binary body data is counted as octets, not decoded as header text.
Host presence is not Host authority, URI validity, DNS or routing verification.

CRLF is the explicit supported profile. Bare LF and obsolete folding are
labelled strict-profile denials, not proof that every recipient violates HTTP.
[RFC 9112 parsing and fields](https://datatracker.ietf.org/doc/html/rfc9112#section-2.2)

Identical repeated or comma-list Content-Length values produce a normalization
warning. Conflicting or nondecimal values are adverse. Transfer-Encoding with
Content-Length produces a conflict warning; an otherwise supported chunked
body uses its chunk boundary, not the declared length. Such warnings never
prove smuggling. Requests with neither framing field have a zero-length body.
[RFC 9112 framing](https://datatracker.ietf.org/doc/html/rfc9112#section-6.3),
[RFC 9110 lengths](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6)

Chunked must occur once and last. Data lengths, data CRLF, zero chunk and trailer
termination are checked without allocating a declared body size. Chunk
extensions and other transfer codings are incomplete in this software subset.
If another coding precedes final chunked, framing can still be complete while
the overall analysis remains incomplete. `body_payload_bytes` counts chunk
data after removing framing only; it never claims decompression or application
decoding. [RFC 9112 chunked coding](https://datatracker.ietf.org/doc/html/rfc9112#section-7.1)

Coding-list delimiters respect quoted parameter values and backslash quoted
pairs, so a quoted comma is not invented as another coding. This is only
bounded delimiter recognition, not complete parameter validation or transfer
decoding. Unterminated quotation boundaries remain conservatively incomplete.
[RFC 9110 transfer parameters](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4)

Trailers remain separate. A fixed deny set covers known framing, routing,
authentication and content-format fields. Other fields generate a warning that
their semantics are unverified, rather than silently authorizing their use.
[RFC 9110 trailer limitations](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1)

Unconsumed suffix octets are counted but never parsed as another request or
rewritten into a payload. CONNECT, Upgrade, non-origin targets, other versions,
HTTP/2 and HTTP/3 remain unsupported. Optimistic protocol-transition behavior
is not simulated. [RFC 9931 transition considerations](https://datatracker.ietf.org/doc/html/rfc9931)

## Costs and native integrity

Fixed software limits are 256 KiB supplied bytes, 64 KiB per header or trailer
section, 8192 bytes per line, 256 headers, 1024 chunks including the zero chunk,
128 trailers, 32 coding entries and 256 length values. Numeric declarations
outside signed64 produce an incomplete result, not an invented HTTP maximum.
Leading zeros are removed before bounded numeric conversion.

Native JSON is bounded to 1 MiB, 65,536 visited nodes and depth 12. Structural
punctuation, escaped strings and repeated subtrees are charged before
serialization or hashing. Native aliases, subclasses, excessive integers,
cycles, floats, duplicate JSON keys and unknown fields fail closed. Canonical
base64 decode and re-encode must agree before parser or hash entry.

The owned `HttpRequestFramingAnalysis` supports `to_dict`, `to_json`,
`from_dict` and `from_json`. Metadata replay checks exact native fields,
software bounds, ranges, chunk joins, completion accounting, effect flags and
content address. It does not prove the declared byte-source facts.

`verify_supplied_http_request_framing(report, model=model)` separately
recomputes the entire report from the original supplied bytes and compares
complete canonical documents. Coherently readdressed metadata cannot replace
that source replay. Neither operation authenticates provenance or target truth.

Outcomes are `pass`, `warnings`, `violations` or `incomplete` for this subset.
An incomplete result preserves any violations and warnings already observed.
All results retain `server_vulnerability_proven`, `live_use_approved` and
`qualification_claimed` as `false`. Authority, target, execution, routing,
qualification, deployment and provider effects remain `none`. No runtime
admission, signature, assessment finding or independent qualification is issued.
