# Supplied API object-level authorization projection

This R0 partial component serves existing specialist `AOE-GB-D06-S09`,
capability `api.authorization.object-level`, vector `AV-GB-D06-S09-01`, package
`IWP2-AOE-GB-D06-S09`, and wave `IW2-001`. It adds partial A7.4 offline
evidence only. It does not complete the specialist or any qualification,
independent-validation, or live-use gate.

This leaf compares caller-supplied access outcomes with caller-supplied object
ownership, tenant membership, and exact action-policy rules. It addresses
whether a declared subject could access a declared object under those
premises. The separate property-authorization leaf compares before and after
JSON property values against write-role rules. Neither leaf authenticates a
role, object, policy, or server outcome.

## Source model and assessment

`analyze_api_object_authorization(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON source with exactly these fields:
`schema_version` equal to `v1`, `facts_complete`, `policy_complete`, `subjects`,
`objects`, `policy_rules`, and `access_outcomes`. Subjects declare a
`subject_id` and nullable `tenant_id`.
Objects declare an `object_id`, nullable `owner_subject_id`, and nullable
`tenant_id`. Rules declare a unique `rule_id`, exact `action`, owner relation
(`owner` or `non_owner`), tenant relation (`same_tenant` or
`different_tenant`), and `allow` or `deny` decision. Outcomes declare a unique
`observation_id`, subject, object, action, and `allowed`, `denied`, or `unknown`
result. All IDs and collections are bounded; duplicate JSON keys, extra fields,
unsupported values, and unbounded input are rejected.

The projection compares subject and object IDs for ownership and tenant IDs
for tenant relation. When both completeness flags are true and all referenced
facts and outcomes are resolvable, a matching rule or complete-policy default
deny gives a declared expected decision. An opposite supplied outcome is a
`candidate_policy_contradiction`; an aligned outcome is `declared_consistent`.
Incomplete premises, missing subjects or objects, null ownership or tenant,
conflicting exact rules, and unknown outcomes remain `unknown`. In particular,
an incomplete policy cannot produce a false negative by treating an absent
rule as a real denial.

These are comparisons among supplied declarations, not evidence of an API
object-level bypass, real target state, effective policy, or live exploit. The
report contains source digest, byte count, relation labels, rule IDs, counts,
limitations, and no-effect flags. It does not call a URL or include a target
binding. `verify_api_object_authorization(report, *, source_content,
source_id)` replays exact original bytes; a self-addressed report alone is not
source provenance.

`analyze_supplied_api_object_authorization(model)` is the catalog adapter.
Its exact native model has `source_id` and `source`, with `source` matching
`component_fixture()`. The checked synthetic common-envelope request is
`examples/offline-api-object-authorization-component.json`. Its R0 dry run has
empty network, filesystem, process, and credential resources. No target,
network, process, credential, execution, deployment, routing, qualification,
or authority effect is granted.
