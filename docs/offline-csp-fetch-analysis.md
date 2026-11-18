# Supplied CSP external-fetch predicates

This additive partial component computes inert predicates from supplied data. It
does not load a page, send a request, execute a browser or approve a fetch.

## Ownership and API

Component `csp_supplied_external_fetch_predicates` belongs to
`AOE-GB-D05-S14`, capability `army.gb.d05.s14`, vector `AV-GB-D05-S14-01`,
work package `IWP2-AOE-GB-D05-S14`, wave `IW2-014`. Its commander is
`AOE-GB-D05-CMD`, group owner `AOE-HQ-04`, independent validator `AOE-HQ-34`.
The captured blueprint is
`sha256:519eecb0d32d95081a3bb2e04dc431d5ce71a47f1f65247f6f5e8d875a1fff43`.
This is A7.4 partial offline evidence, not qualification or gate completion.
An integrating dispatcher must select this component explicitly; the existing
CORS component and its profile default are unchanged.

The pure public functions are:

- `analyze_supplied_csp_fetch(model)`
- `analyze_supplied_csp_fetch_bytes(*, model_bytes)`
- `verify_supplied_csp_fetch_analysis(report, *, model)`
- `component_fixture()`, which returns fresh synthetic data

They return a frozen `CspFetchAnalysis`, with `from_dict`, `from_json`,
`to_dict` and `to_json`. Unsupported closed shapes, cost excess and false
replays raise `CspFetchAnalysisError`. No callbacks or runtime resources exist.

## Exact model

```json
{
  "schema_version": 1,
  "protected_origin": {"scheme": "http", "host": "app.example.test", "port": null},
  "policy_list_complete": true,
  "policies": [
    {"policy_id": "policy.one", "disposition": "enforce", "serialized_policy": "img-src 'self'"}
  ],
  "queries": [
    {"query_id": "query.one", "destination": "image", "redirect_count": 0,
     "url": {"scheme": "https", "host": "app.example.test", "port": null}}
  ]
}
```

Every object is closed and every field is required. Arrays preserve source
order. IDs are distinct within their own arrays. Disposition is `enforce` or
`report`; destination is `image`, `font`, `media` or `connect`. The declared
policy list can be empty. Its completeness is an unauthenticated assertion.
Each serialized string is one policy, not a comma-separated HTTP header list.

URLs and the origin are caller-normalized HTTP(S) tuples. A null port means the
normalized default; an explicit native port must be nondefault and 1..65535.
Hosts use lowercase ASCII DNS labels, each 1..63 bytes, total 1..253 characters,
without a trailing dot or an all-numeric/IP spelling. There is no URL parsing,
IDNA conversion, authenticated DNS or public-suffix inference. These are local
software restrictions, not universal CSP syntax judgments.

## Pinned matching subset

The implementation follows the algorithms in the
[CSP3 working draft dated 2026-09-16](https://www.w3.org/TR/2026/WD-CSP3-20260916/),
specifically [policy parsing](https://www.w3.org/TR/2026/WD-CSP3-20260916/#parse-serialized-policy),
[Fetch integration](https://www.w3.org/TR/2026/WD-CSP3-20260916/#integration-with-fetch),
[URL matching](https://www.w3.org/TR/2026/WD-CSP3-20260916/#match-url-to-source-list)
and [fallback](https://www.w3.org/TR/2026/WD-CSP3-20260916/#directive-fallback-list).

Directive names are ASCII-lowercased, the first duplicate wins, and only ASCII
whitespace separates tokens. The four selected fetch directives fall back to
`default-src`; absent restrictions differ from an empty source list. Supported
expressions are pathless HTTP(S) schemes/hosts, `'self'`, `'none'`, `*`, wildcard
subdomains and wildcard ports. Sources combine by OR; enforced policies combine
by conjunction. Report-only observations never block the overall predicate.

Scheme upgrades are asymmetric. `'self'` supports a default-port HTTP-to-HTTPS
upgrade. Omitted host-source ports match normalized default ports; an explicit
source `:80` does not match an HTTPS default `:443`. This follows current
section 6.7.2.11, not the introductory older port example. A wildcard subdomain
excludes its apex and requires the dot suffix boundary. Source DNS case is
insensitive; tuple hosts must already be canonical.

Paths, redirects, unsupported expressions and unsupported directive semantics
are unassessed. An unresolved enforced policy or incomplete policy list
withholds the overall conclusion, even alongside a known supported denial.
Unselected source expressions remain labeled without becoming another
destination's restriction. Per-policy supported-source observations are not
full-policy conclusions.

## Cost, integrity and limitations

The model is bounded to 256 KiB, 8192 native occurrences and depth 16; the report
to 1 MiB, 65536 occurrences and depth 20. Limits include 16 policies, 128 queries,
64 semicolon segments per policy, 64 sources per active directive, 2048 total
active sources, 512 bytes per source expression, 8192 bytes per string, and
declared redirect counts 0..128. Positive redirects are retained but unassessed.
All native integers are signed 64-bit; schema, port and counter shapes are exact,
so booleans/floats/subclasses do not alias them.

Each public operation shares a 16777216-unit software work budget. Native
capture charges repeated subtrees, structural punctuation, escaped ASCII,
nodes and depth before retaining copies. Raw input charges byte copying and
lexical string/integer/container costs before JSON decoding; duplicate members
are rejected, including escaped duplicate names. Cycles, nonnative collections,
floats, unbounded integers and out-of-profile controls are denied. Matching scans
are charged before token retention. Cumulative output rows are bounded before
append. Complete output, replay, equality, encoding and address costs are
reserved before any digest at all eight public boundaries.

The original model is embedded. Model and report addresses use distinct domains;
export and reconstruction rederive all semantics, not merely a hash. The
separate-original verifier additionally compares the caller's original model.
All outputs are detached. These checks are integrity, not authentication,
same-process containment, source currentness or authenticated policy delivery.

The report retains supplied policy strings and host identifiers and is not
sanitized for publication. It does not inspect response handling, opaque origins,
inline/script/style behavior, nonce/hash/strict-dynamic semantics, policy-driven
upgrades, sandbox, browser execution, fetch eligibility, actual permissions,
CSP bypasses or XSS safety. All authority, browser, network, process, provider,
credential, routing, publication and qualification effects remain `none`;
every corresponding claim flag is native `false`.

The focused tests use literal matching tables and independent small tuple/Boolean
oracles, as well as native/raw/resource bounds, source swaps, coherent false
reports and detached replay. No browser or external endpoint is contacted.

The public fixture yields `CFA-E502807486A313E8A1834D615A80C434`, report digest
`sha256:e502807486a313e8a1834d615a80c434f802a41c8f3d8109414dde8af4d0c4c1`
and model digest
`sha256:ae6c29b1acf4531b3ad5ea399ab4351275f0dfce254e66e5793d17cf92c6ed20`.
Its three supplied query conclusions are allowed, blocked and allowed, in that
order. The separate report-only policy observes nonmatches without enforcing
them. These are literal synthetic regression vectors, not browser observations.
