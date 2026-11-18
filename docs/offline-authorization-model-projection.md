# Supplied Authorization Model Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S13`, capability `identity.authorization.rbac-abac-rebac`, vector
`AV-GA-D03-S13-01`, work package `IWP2-AOE-GA-D03-S13`, and wave `IW2-014`.
The domain commander is `AOE-GA-D03-CMD`, and the independent validator
reference is `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts bounded caller-supplied principals, role sets,
principal and resource attributes, direct principal-resource relations,
allow or deny rules, and reported authorization outcomes. Each rule is a
conjunction of an action with optional RBAC, ABAC, and direct ReBAC conditions.
The projector evaluates only those declared facts. It does not expand a
relationship graph or interpret product-specific policy languages.

Missing role, attribute, or relation facts remain unresolved when the relevant
completeness flag is false. A possibly matching deny cannot be overridden by
a definite allow, and overlapping definite allow and deny rules are reported
as a conflict with an unknown projected decision. Complete policy with no
matching or possibly matching rule yields a declared default deny. A difference
between the projected decision and a separately reported outcome is only a
`candidate_declared_policy_conflict`.

`analyze_supplied_authorization_model` emits a content-addressed unsigned
report. Verification replays a separately retained original model through
`verify_supplied_authorization_model` or its bounded JSON-byte variant. The
report's embedded source does not authenticate itself. A synthetic dispatcher
input is in
[`offline-authorization-model-projection-component.json`](../examples/offline-authorization-model-projection-component.json).

Completeness flags, identity, policy, relation facts, and reported outcomes are
caller declarations. No effective access, target response, policy deployment,
finding, qualification, or authorization is established. The module performs
no network, provider, target, tool, credential, process, or filesystem action.
