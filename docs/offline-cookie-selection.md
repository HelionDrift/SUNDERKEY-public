# Supplied retained-cookie candidate predicates

This partial offline algorithm evaluates declared retained cookie metadata against
declared request metadata. It observes domain, path, Secure and HttpOnly predicates
individually. A match means only `matches_supplied_predicates`, not that a browser
accepted, retained or transmitted a cookie, nor that a server authorized anything.

Its existing Army ownership is `AOE-GB-D05-S11`, capability
`web.browser-auth-session`, vector `AV-GB-D05-S11-01`, package
`IWP2-AOE-GB-D05-S11`, wave `IW2-011`, commander `AOE-GB-D05-CMD`, group owner
`AOE-HQ-04` and independent validator `AOE-HQ-34`. The pinned blueprint digest is
`sha256:b83a03607604ae4f7f4edf728b5a6baed306bddbf63bd5a372c7c2b15e0c79f8`.
This is partial A7.4 evidence under the existing `web.browser-auth-session`
boundary, not specialist completion, operational capability or qualification.

## Supplied closed model

`component_fixture()` returns a fresh wholly synthetic example. The exact root
fields are `schema_version: 1`, `cookies` and `requests`. Each retained cookie is:

```json
{
  "cookie_id": "retained-synthetic-cookie",
  "name": "SID",
  "domain": "example.invalid",
  "path": "/app",
  "host_only": false,
  "secure": true,
  "http_only": true
}
```

Each request is:

```json
{
  "request_id": "declared-synthetic-request",
  "host": "api.example.invalid",
  "path": "/app/item",
  "secure_transport": true,
  "http_api": true
}
```

These are supplied metadata premises, not parsed Cookie or Set-Cookie fields,
observed browser state, validated URL acquisition, TLS evidence or independent
HTTP-API classification. Unknown fields are rejected. All objects, arrays,
strings, integers and booleans must have exact native types; numeric boolean
aliases and subclasses do not normalize into supported input.

Hosts and domains use the same narrow ASCII premise: lowercase LDH DNS labels
without a leading or trailing dot, or the exact canonical spelling of an
unbracketed, unscoped IPv4 or IPv6 address. There is no IDNA conversion or public
suffix verification. Punycode-looking LDH labels remain declared ASCII labels,
not validated internationalized names. Domain attributes are not parsed and
leading dots are not stripped. Exact canonical IP equality is supported.

Names are nonempty bounded ASCII HTTP tokens. Paths are nonempty absolute
ASCII URI-path spellings containing pchar, slash and well-formed percent escapes.
This closed subset excludes whitespace, query and fragment delimiters, backslash
and malformed escapes. Literal spelling, case, repeated slashes, dot segments and
percent-escape spelling are retained. Nothing is percent-decoded, normalized or
converted into a default cookie path.

Cookie and request IDs must be unique within their own arrays. A duplicate
`(name, domain, path)` is rejected even when its other flags differ. This is a
closed declared-retained-model constraint, not a universal browser storage,
replacement or cookie-acceptance verdict. Same names on different supplied
domains or paths are supported; name case is retained.

## Finite predicates and result

The implementation follows the domain-match and path-match predicates in
[RFC 6265 section 5.1.3](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.3),
[section 5.1.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.1.4) and the
selection predicates in
[section 5.4](https://www.rfc-editor.org/rfc/rfc6265.html#section-5.4).

Host-only cookies require exact host equality. Other cookies match by equality,
or by a suffix preceded by a dot when the request host is not an IP address.
Path matching requires equality, a matching prefix ending in slash, or a matching
prefix followed by slash in the request path. Secure matches when that flag is
false or supplied `secure_transport` is true. HttpOnly matches when that flag is
false or supplied `http_api` is true. All four observations are retained even
if another predicate fails.

Every cookie/request pair has exact source IDs, the four boolean observations,
domain/path basis codes and the conjunction outcome. The array is request-major
and preserves declared cookie order for source correlation. It is not Cookie
header ordering or transmission order. Empty retained arrays produce zero pairs;
at least one declared request is required.

The report embeds a detached copy of the original model, a canonical model
digest, the derived observations, exact software bounds, ownership coordinates
and limitations. Every effect is `none` and every proof, use, vulnerability or
promotion flag is native `false`. No cookie values or parsed content are accepted
or included. The canonical report address has the `CKS-` prefix and leaf domain
`sunderkey.offline-cookie-selection.v1`.

## APIs and replay

`analyze_supplied_cookie_selection(model)` returns a frozen
`CookieSelectionAnalysis`. `analyze_supplied_cookie_selection_bytes(*,
model_bytes)` accepts exact native ASCII JSON bytes, but reads no resource.
The wrapper offers detached `to_dict()`, canonical `to_json()`, `from_dict()` and
`from_json()`, plus `analysis_id` and `analysis_sha256` properties. Missing or
malformed wrapper storage fails through `CookieSelectionError` at use.

Every exported or parsed report reconstructs its conclusions from its embedded
source. A coherently readdressed false conclusion is not accepted merely because
its hash is consistent. Canonical native model identity, not raw JSON whitespace,
binds the source. `verify_supplied_cookie_selection(report, *, model)` additionally
reconstructs against the separately supplied original model and returns a new
detached wrapper. An internally consistent substituted source can describe itself
but cannot verify against a different original. Hashes are content correlation,
not source authenticity, retention proof or current browser authority.

## Software-cost bounds

Each native or reconstructed model/report is limited to 1 MiB of canonical ASCII
JSON, 32,768 nodes, depth 16 including scalar nodes, and 1,024 bytes per string.
Limits are at most 128 cookies, 64 requests and 8,192 declared pairs. Hosts are at
most 253 bytes, paths 1,024 bytes, names 128 bytes and IDs 128 bytes. The cumulative
work ceiling is 4,000,000 charged steps per reconstruction. These are local cost
bounds, not cookie authority, browser limits or availability guarantees.

Native traversal charges repeated shared subtrees, escaped quotes/backslashes,
punctuation and signed 64-bit integers before copying or serialization. Cycles
fail closed. Raw intake checks bytes, scalar lexical lengths, strings, nodes and
scalar-inclusive depth before the JSON decoder; duplicate keys, fractions,
nonfinite numbers and out-of-range integers are rejected. Source validation and
character/pair work are charged before pair evaluation. Derived rows are checked
against cumulative byte/node limits before retention. The complete report,
including fixed-width source and report identities, final body serialization and
both digest inputs, is budgeted before any digest. Four complete-report work
allowances cover raw checking, ownership capture, canonical comparison and final
export during wrapper replay. Report or work limits can reject a model below the
individual pair ceiling; none of these denials is a cookie predicate failure.

## Explicit exclusions

There is no Cookie/header generation, Set-Cookie acceptance, value processing,
expiry, clock, eviction, storage, replacement, creation/access-time sorting,
SameSite, PSL, IDNA conversion, partitioning, cookie-prefix enforcement or
browser-specific behavior. No credentials, files, callbacks, browser engines,
processes, network, provider or target operations are used. A matched declaration
is neither observed transmission nor a vulnerability, server authorization,
qualification, readiness, live authority or independent authentication claim.
This pure consistency boundary is not an arbitrary in-process memory sandbox.
