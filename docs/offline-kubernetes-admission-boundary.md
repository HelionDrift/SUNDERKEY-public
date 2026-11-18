# Supplied Kubernetes admission policy projection

This R0 component belongs to profile `AOE-GC-D15-S08`, capability
`army.gc.d15.s08`, vector `AV-GC-D15-S08-01`, package
`IWP2-AOE-GC-D15-S08`, and wave `IW2-010`. Its component ID is
`kubernetes_supplied_admission_policy_projection`. It contributes partial
A7.4 evidence only and does not complete or qualify the specialist.

The schema version 1 model supplies a finite set of validating policy and
validating webhook declarations plus synthetic create/update request outcomes.
A policy selects an exact resource kind, namespace, operation and optional
post-mutation field/value pair. It declares an allow, deny or unknown effect.
Webhooks additionally declare availability and `fail` or `ignore` behavior.
Native validating policies must be declared available and cannot use webhook
failure behavior. An allow policy is a non-veto, not a grant overriding another
deny.

Requests carry supplied post-mutation scalar fields, builtin or CRD family,
operator-generated status, completeness of mutation and operator context,
CRD schema completeness, and a supplied admission outcome. No mutation is
performed. A complete CRD request needs a complete declared schema context;
an operator-generated request needs a complete declared reconciliation
context. The model does not evaluate CEL, execute webhooks, run operators,
interpret CRD schemas or determine actual Kubernetes admission ordering.

With complete policy inventory and request context, a matching available deny
or unavailable fail-closed webhook expects rejection. An unavailable
fail-open webhook does not veto. Unknown matching policy or availability makes
the result unknown. No modeled veto does not guarantee admission because
builtin validation, authorization, quotas and other stages are not modeled.
A supplied admitted outcome opposite an expected reject is a candidate
declaration mismatch, not an observed bypass. Incomplete
policy inventory, mutation, operator, CRD or observation premises yield
`unknown`, not a candidate. A complete modeled policy set with no veto also
produces `unknown` for the overall admission outcome.

`analyze_supplied_kubernetes_admission_boundary` accepts a native model;
`analyze_supplied_kubernetes_admission_boundary_bytes` accepts bounded ASCII
JSON bytes. `verify_supplied_kubernetes_admission_boundary_analysis` rederives
a report against separately supplied original premises. `from_json` validates
internal derivation from the embedded source, but cannot establish that the
embedded source is the approved original. Reports carry exact source model,
domain-separated source and report addresses, bounds, false verification
flags, limitations and `none` effects. The synthetic R0 request is
`examples/offline-kubernetes-admission-boundary-component.json`.

This leaf contacts no Kubernetes API, webhook, operator, credential, network,
process or target. It establishes no live finding, authority, qualification
or positive use.
