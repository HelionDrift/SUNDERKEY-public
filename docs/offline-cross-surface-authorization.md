# Supplied Cross-Surface Authorization Decisions

The `AOE-GE-D23-S07` partial specialist compares caller-supplied authorization
decisions across two to eight named surfaces. It groups records only when
their opaque `principal_ref`, `action_ref`, and `resource_ref` values match
exactly. One surface cannot provide two decisions for the same key.

An explicit `identity_mapping_complete` assertion controls interpretation.
If that assertion is false, the comparison remains unresolved. Unknown
decisions also remain unresolved. With complete asserted mapping, differing
declared outcomes produce only a `candidate_declared_decision_difference`.
The assertion and decisions are not independently verified. A difference may
be legitimate policy, stale data, or mismatched identity mapping. It is not
proof of an authorization bypass or target behavior.

The exact native model is bounded to 256 decisions and requires opaque
`ref:` labels. Those labels are a format guard, not a guarantee that a caller
removed sensitive content. The replay report embeds the original model and
has no file, network, process, credential, target, publication, execution,
or qualification effect. The [synthetic example](../examples/offline-cross-surface-authorization-component.json)
contains only declared decisions.
