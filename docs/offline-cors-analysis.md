# Supplied CORS negotiation and exposure analysis

`sunderkey.offline_cors_analysis` evaluates a finite part of the CORS protocol
on caller-supplied parsed HTTP metadata. It neither obtains that metadata nor
executes a request or browser. This is partial offline algorithm evidence for
AOE-GB-D05-S14, `army.gb.d05.s14`, AV-GB-D05-S14-01, IWP2-AOE-GB-D05-S14 and
IW2-014. Its command is AOE-GB-D05, commander AOE-GB-D05-CMD, group commander
AOE-HQ-04 and independent validator AOE-HQ-34. The blueprint is
`sha256:519eecb0d32d95081a3bb2e04dc431d5ce71a47f1f65247f6f5e8d875a1fff43`.
It contributes only partial evidence to A2.5 and A7.4, not completion of the
SOP, CORS and CSP specialist or any candidate qualification.

## Standard and supplied premises

Semantics are pinned to WHATWG Fetch commit
`357bd98924d94b81fbe8608192a2ee1f123b82f4`. The
[rendered snapshot](https://fetch.spec.whatwg.org/commit-snapshots/357bd98924d94b81fbe8608192a2ee1f123b82f4/),
[official source](https://github.com/whatwg/fetch/blob/357bd98924d94b81fbe8608192a2ee1f123b82f4/fetch.bs)
and [raw source](https://raw.githubusercontent.com/whatwg/fetch/357bd98924d94b81fbe8608192a2ee1f123b82f4/fetch.bs)
describe the CORS check, CORS-preflight fetch and CORS-filtered response.
[RFC 9110 sections 5.6.1 through 5.6.3](https://httpwg.org/specs/rfc9110.html#field.parsers)
define the token, comma-list and SP/HTAB whitespace subset used here.

The supplied serialized origin is a premise, not a URL that this module
normalizes or independently verifies. `null` is a legitimate literal opaque
origin premise and is not the same as an absent Allow-Origin field. `*` is
rejected as a request-origin premise. Exact byte-text comparison is used;
the module does not infer an origin from any target address.

Credentials mode is `omit`, `same-origin` or `include`, not actual credentials.
The method must already have Fetch's known-method normalization. Custom
methods retain their case. Unsafe request-header names are a complete supplied
projection: values, safelist classification and the browser's request
construction are not inspected. Names alone cannot establish that projection.

`preflight_required` and `use_cors_preflight` are distinct native booleans.
The first is the caller's requirement premise. The second is the forced
preflight flag used by the normative absent Allow-Methods fallback. Forced
preflight with an explicit false requirement is rejected. Neither flag proves
browser eligibility or the state of a preflight cache. A false requirement
produces `not_required_by_supplied_premise`, not proof that a browser omits it.

## Closed model and API

The model is `{schema_version: 1, cases: [...]}`. Each case has exactly
`case_id`, `request`, `preflight_response` and `actual_response`.

`request` has exactly `source_id`, `serialized_origin`, `credentials_mode`,
`method`, `unsafe_header_names`, `preflight_required`, `use_cors_preflight` and
`projection_complete`. The last flag is a supplied completeness assertion.

Both nullable response objects have `source_id`, native final `status` from
200 through 599, ordered `cors_fields` and `headers_complete`. Actual responses
also have `response_header_names`, a unique case-insensitive name inventory.
The five supported policy-field values are Allow-Origin, Allow-Credentials,
Allow-Methods, Allow-Headers and Expose-Headers, with their full
`Access-Control-` prefix. A field is exactly `{name, value}`. Other response
fields are represented by names only, not their values. Inventory and supplied
policy-field names must agree when the metadata is declared complete.

Input strings are supplied parsed metadata, not raw HTTP wire bytes. Parsing
HTTP messages, trimming wire field values and classifying request headers are
outside this module. The supported policy values are ASCII; CR, LF, NUL,
non-ASCII and other controls except HTAB are rejected. This intake restriction
is not a claim that every unsupported octet has a particular browser outcome.

Public APIs are `analyze_supplied_cors(model)`,
`analyze_supplied_cors_bytes(*, model_json: bytes)` and
`verify_supplied_cors_analysis(report, *, model)`. They return the exact detached
`CorsAnalysis` wrapper; failures use `CorsAnalysisError`. `component_fixture()`
returns a fresh wholly synthetic model. The component ID is
`cors_supplied_negotiation_and_exposure` and dispatcher payload is `{model}`.

## Derived checks and limits of conclusions

Each report row has separate `preflight_check` and `actual_response_check`,
`exposed_header_names` and `comprehensive_share_result`. Preflight uses the
original request's credentials mode and needs an OK status. Actual response
sharing does not require a successful HTTP status; a supplied 403 can pass
the CORS check. Success of either check does not establish the other or that
an actual browser sent or received the corresponding exchange.

Ordered singleton duplicates cannot become one valid Allow-Origin or
Allow-Credentials value. List fields combine instances in order; bounded empty
members are ignored and only SP/HTAB is treated as list whitespace. Methods
are case-sensitive, header names case-insensitive, and Allow-Credentials must
be the exact lowercase `true` when credentials mode is `include`.

Wildcard method/header permissions depend on credentials mode. Authorization
must be explicitly allowed even when Allow-Headers contains `*`. Safelisted
methods retain their normative exception. Absent Allow-Methods with the forced
flag differs from an explicitly empty list.

Exposure selects present safelisted names plus explicitly exposed names.
Expose-Headers `*` is a wildcard only outside `include`; with `include` it is
a literal header name. Set-Cookie and Set-Cookie2 are always omitted, including
under wildcards or explicit listing. An invalid optional exposure list leaves
only safelisted names and does not veto a successful actual CORS check. This
syntax fallback does not apply to software-cost exhaustion: a token longer
than the supported 128-byte ceiling raises `CorsAnalysisError`, even when its
characters otherwise satisfy the HTTP token grammar.

Incomplete request projection or response metadata withholds affected
conclusions and any comprehensive pass. Complete supplied checks may produce
`passes_supplied_checks`; this is conditional metadata mathematics, never a
share grant, live access proof, authorization or vulnerability verdict.

Reports contain the owned model, its canonical SHA, derived rows, fixed cost
ceilings, limitations and false positive-use/qualification flags. Every effect
is `none`. Constructors and parsers recompute from the embedded model rather
than trusting rehashed derived rows. Verification additionally recomputes
against the separately supplied original model. Source IDs, hashes and
completeness flags authenticate nothing. JSON whitespace may normalize, while
the exact canonical native source, arrays and original field order remain
bound. Returned dictionaries and wrappers do not alias caller inputs.

## Software-cost ceilings

Each supplied model or report has a 1 MiB canonical/raw document ceiling,
depth 16 and 32,768 native/raw nodes. String intake is at most 4,096 UTF-8 bytes.
Repeated shared subtrees and escaped serialization bytes are charged before
serialization. Raw JSON depth, scalar lexical limits, escaped string size and
node count are checked before decoding; duplicate keys, floats, nonfinite
numbers, aliases and integers outside signed 64-bit are rejected.
The complete constructed report, including reserved fixed-width source and
report addresses, is checked and charged against native byte/node ceilings
before any digest. A bounded source can still exceed a derived report ceiling;
that rejection publishes no report and is not a CORS-policy conclusion.

There are at most 64 cases, 32 policy-field instances per response and 4,096
aggregate instances. Names are at most 128 ASCII bytes, request unsafe names
at most 32 per case and actual-response names at most 64 per case. Parsed
tokens and exposed names each have an aggregate 4,096 ceiling. An independent
charged work ceiling of 1,000,000 covers canonical visits/serialization size,
hash input, list scans, semantic matching and bounded output sorting. Work can
reject input below another ceiling. These are local software-cost limits, not
browser, server, permission or security-policy thresholds.

There is no response body, credential value, network callback, browser engine,
provider, process or filesystem access. SOP, CSP, redirects, service workers,
preflight caches, request-value safelist classification and full Fetch/HTTP
validity are excluded. No source authenticity, server authorization, finding
publication, independent browser behavior, operational readiness or
qualification follows from this analyzer or its synthetic tests.
