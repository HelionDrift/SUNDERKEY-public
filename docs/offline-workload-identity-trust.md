# Supplied workload identity trust projection

This R0 partial component belongs to existing specialist `AOE-GC-D14-S10`,
capability `cloud.workload-identity-metadata`, vector `AV-GC-D14-S10-01`, package
`IWP2-AOE-GC-D14-S10`, and wave `IW2-013`. It contributes partial A7.4 offline
evidence only. It does not complete the specialist, qualification, independent
validation, or any live-use gate.

The component projects caller-supplied issuer, subject, audience, and requested
role values through caller-supplied exact trust rules and role bindings. These
are declarations, not acquired or authenticated cloud configuration. It does
not parse or validate a token, verify a signature, resolve a metadata endpoint,
contact a cloud provider, or prove effective privilege. A declared exact match
is not evidence that a real workload can assume the role.

## Source model and results

`analyze_workload_identity_trust(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON source. Its closed `v1` model has `claims`,
`trust_rules_complete`, `trust_rules`, `role_bindings_complete`, and
`role_bindings`. Each claim has a unique `claim_id`, an `issuer`, `subject`,
`audience`, and `requested_role_ref`. Each trust rule has a unique `rule_id`,
the same three exact-match fields, and an `allow` or `deny` effect. Each role
binding has a unique `binding_id`, a declared allow `rule_id`, and a `role_ref`.
IDs and text are bounded. Duplicate JSON keys, extra fields, unsupported
values, dangling bindings, and excessive arrays are rejected.

For each claim and requested role, the report gives `declared_exact_match`,
`declared_denied`, or `unknown`, plus a specific basis and matched rule and
binding IDs. Exact allow and binding support a declared match only when trust
rules are declared complete. An exact deny or no matching rule can support a
declared denial under complete trust rules. No matching role binding supports
a denial only when bindings are declared complete. Incomplete rule or binding
lists and conflicting exact allow and deny rules remain unknown. No provider
precedence or effective authorization is inferred.

The report binds the raw source digest, byte count, source ID, projections,
counts, limitations, and no-effect flags. It omits issuer, subject, and audience
values. `verify_workload_identity_trust(report, *, source_content, source_id)`
replays the original bytes; a self-addressed report alone is not source
provenance. `analyze_supplied_workload_identity_trust(model)` is the catalog
adapter. Its exact native model has `source_id` and a `source` object matching
`component_fixture()`; it canonicalizes the source before byte-level analysis.

The inert common-envelope request is
`examples/offline-workload-identity-trust-component.json`. Its R0 dry run has
empty network, filesystem, process, and credential resources. Analysis and
replay have no network, process, credential, target, deployment, routing,
qualification, or authority effects.
