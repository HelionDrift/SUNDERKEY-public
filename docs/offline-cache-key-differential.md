# Supplied HTTP cache-key differential

This R0 partial component serves existing specialist `AOE-GB-D05-S04`,
capability `army.gb.d05.s04`, vector `AV-GB-D05-S04-01`, and wave `IW2-004`.
It is separate from the existing HTTP freshness arithmetic. It neither
observes nor writes a cache and cannot verify cache poisoning or deception.

## Declared projection

`analyze_supplied_cache_key_differential(model)` accepts exact native schema
version 1, one declared `key_rule`, and one to 64 supplied left/right pairs.
The rule declares whether method, scheme, host, path, and query enter the base
key, plus sorted unique nonsensitive lowercase header names. Each side holds
synthetic request strings and single-value headers, a response signature,
declared `Vary` selectors or an unknown/wildcard state, and a declared
`no_store` boolean or unknown state. Sensitive header names are rejected.
These are premises, not observed cache configuration, requests, responses,
storage or reuse. Unknown keying beyond the supplied rule is not modeled.

The analyzer first compares declared base-key fields. If they match, it
compares equal declared `Vary` selectors and their request values. A differing
response signature under an assessed key collision yields
`candidate_key_collision_with_distinct_signatures`. Distinct declared keys
yield `distinct_declared_keys`. Unknown or wildcard `Vary`, inconsistent
selectors, `no_store`, or unknown storage status withhold a candidate and
produce explicit uncertainty. The result never predicts a deployed cache's
key, variant selection, storage, reuse, or exploitability.

## Source binding

Reports retain the complete bounded native model, a domain-separated source
digest, observations, false live-verification flags, and `none` effects.
`from_dict`, `from_json`, and the verifier rederive the report; independent
verification also requires the original model. The checked example is
`examples/offline-cache-key-differential-component.json`. It is synthetic,
contains no credentials or target destination, and grants no action authority.
