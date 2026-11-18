# Supplied HTTP cache freshness arithmetic

This partial offline component calculates explicit freshness lifetime and the
conservative age formula from supplied, valid integer premises. A freshness
comparison is arithmetic only. It is not cacheability, permission to store or
reuse a response, observed cache state, current authority or qualification.

The existing Army binding is `AOE-GB-D05-S02`, `army.gb.d05.s02`,
`AV-GB-D05-S02-01`, `IWP2-AOE-GB-D05-S02`, wave `IW2-002`, commander
`AOE-GB-D05-CMD`, group owner `AOE-HQ-04` and validator `AOE-HQ-34`.
The blueprint digest is
`sha256:03c71eef405c080e094fbab91db4a0b25fe141cf3e581a81c62a51cf2db4da4a`.
This is partial A7.4 evidence, not completion of the specialist or any gate.

## Closed supplied projection

The root is exactly `schema_version: 1` and a nonempty native `cases` array.
Every case has exactly these fields:

```json
{
  "case_id": "synthetic-shared",
  "cache_kind": "shared",
  "request_time_seconds": 1000,
  "response_time_seconds": 1005,
  "evaluated_at_seconds": 1020,
  "date_value_seconds": 998,
  "age_value_seconds": 3,
  "max_age_seconds": 60,
  "s_maxage_seconds": 30,
  "expires_value_seconds": 1100
}
```

`cache_kind` is exactly `shared` or `private`. Instants are exact native signed
64-bit integer UTC epoch seconds or null. Age and max-age deltas are exact native
nonnegative signed 64-bit integers or null. These are already-projected valid
integer values, not HTTP text or independently verified readings. Null Date,
Age, max-age, s-maxage or Expires means the caller explicitly declares that field
absent. Null cannot mean an unknown, invalid, duplicate or unparsed header.
Null request, receipt or evaluation clocks instead means an unavailable premise.
Unknown fields, float/integer aliases, boolean/integer aliases and subclasses
are rejected before new addressing. No ambient clock is consulted.

## Arithmetic and unassessed cases

The scope follows [RFC 9111 section 4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2),
[4.2.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.1) and
[4.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3).
Shared caches select present s-maxage first. Otherwise present max-age wins,
then Expires minus the effective Date. Private caches ignore s-maxage. Zero is
present, not a fallback trigger. A negative Expires lifetime remains negative.
No explicit lifetime leaves the comparison unassessed; no heuristic is invented.

Absent Age contributes zero. Absent Date substitutes the declared response-time
instant. This models the receipt-time convention referenced by RFC 9111 and
[RFC 9110 section 6.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.6.1),
not an observation that a recipient appended Date or possessed a trusted clock.
The effective value and its declared basis are retained in every observation.

The selected conservative age branch is:

```text
apparent_age = max(0, response_time - effective_date)
response_delay = response_time - request_time
corrected_age_value = effective_age + response_delay
corrected_initial_age = max(apparent_age, corrected_age_value)
resident_time = evaluated_at - response_time
current_age = corrected_initial_age + resident_time
freshness_comparison = freshness_lifetime > current_age
```

Equality is not fresh. This is the conservative max branch permitted by RFC 9111,
not a claim that all caches use that branch. Missing clocks or a declared order
other than request <= response <= evaluation leaves the comparison unassessed.
The origin Date may lie ahead of receipt time; only apparent age is clamped.
Partial lifetime or age observations can remain when the other is unassessed.
Every intermediate operation must fit signed 64-bit. Overflow produces an
explicit unassessed reason, never wraparound or an invented infinite age. This
finite arithmetic subset does not implement all HTTP overflow conventions.

`component_fixture()` returns three fresh synthetic cases: shared lifetime 23
equals age 23 and is not fresh; private max-age 60 exceeds age 23; missing explicit
lifetime is unassessed. It does not contain a captured real response.

## API, source replay and finite costs

`analyze_supplied_http_cache_freshness(model)` returns an owned frozen
`HttpCacheFreshnessAnalysis`. The bytes API accepts bounded native ASCII JSON
bytes, without reading files or resources. `to_dict`, `to_json`, `from_dict` and
`from_json` reconstruct the full report from its detached embedded original
model. `verify_supplied_http_cache_freshness_analysis(report, *, model)` also
rederives from separately supplied originals. A coherent source substitution
can describe itself but cannot verify against a different original. The `HCF-`
address and source digest provide content correlation, not source authentication.
Malformed or missing wrapper storage fails through `HttpCacheFreshnessAnalysisError`.

Each model/report is bounded to 1 MiB canonical ASCII JSON, 32,768 nodes, depth
16 including scalars and 256 bytes per string. Cases are limited to 128 with
unique IDs of at most 128 bytes. A derivation has a cumulative 4,000,000-step
work ceiling. Raw lexical lengths, integer grammar, escapes, nodes and depth are
checked before decoding. Duplicate JSON fields are rejected. Native repeated
subtrees, cycles, escaping and structural punctuation are checked before copying.
Rows have cumulative byte/node guards before retention. Complete replay/export
passes and both source/report digest inputs are reserved before the first hash.
Limits are software-cost constraints, not HTTP validity or cache authority.

## Exclusions

No HTTP date/header parsing, duplicate-directive policy, heuristic lifetime,
cache key, Vary, request cache directives, no-cache/no-store permission, storage,
reuse, validation, stale serving or eviction is implemented. Freshness does not
grant any of these permissions. All effects are `none`; every proof, approval
and qualification flag is native false. There are no credentials, callbacks,
network, target, provider, process or actual cache operations. This is neither
clock/source truth nor a generic in-process memory sandbox.
