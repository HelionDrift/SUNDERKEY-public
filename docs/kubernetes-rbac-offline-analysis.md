# Offline Kubernetes RBAC resource analysis

`sunderkey.kubernetes_rbac_analysis` implements one deterministic algorithm
component for `AOE-GC-D15-S04`, capability
`container.kubernetes.rbac-service-account`, vector `AV-GC-D15-S04-01`, and
wave `IW2-006`. It is not a complete candidate, a qualified specialist, an
authenticated cluster snapshot, or an execution adapter. It changes none of
the existing six reference manifests or their identities.

The module evaluates finite resource-request attributes against explicitly
supplied RBAC objects. It has no client, transport, callback, file operation,
credential lookup, policy fetch, discovery, process, signing, or deployment
operation. No Kubernetes command is generated or invoked.

## Interfaces and supplied fixture

```python
analyze_kubernetes_rbac(snapshot: dict, queries: list) -> KubernetesRbacAnalysis
analyze_kubernetes_rbac_bytes(
    *, snapshot_bytes: bytes, queries_bytes: bytes
) -> KubernetesRbacAnalysis
verify_kubernetes_rbac_analysis(
    analysis: KubernetesRbacAnalysis | dict, *, snapshot: dict, queries: list
) -> KubernetesRbacAnalysis
```

The snapshot has exactly one field, `objects`, containing native JSON
`rbac.authorization.k8s.io/v1` Role, ClusterRole, RoleBinding, and
ClusterRoleBinding objects. Role rules, binding subjects, and `roleRef` use
their Kubernetes field names. Objects must have exact identities; duplicate
kind/namespace/name tuples are rejected even when their bodies are equal.
Unknown top-level, rule, subject, reference, and supported metadata fields
are rejected. This is a declared subset, not a general Kubernetes API object
validator. Metadata supports name, namespace, labels, annotations, uid,
resourceVersion, generation, and creationTimestamp. No timestamp or metadata
value is authenticated.

Every query has exactly these fields:

```json
{
  "query_id": "read-pod",
  "principal": "alice",
  "groups": [],
  "namespace": "team-a",
  "resource_scope": "namespaced",
  "api_group": "",
  "resource": "pods",
  "subresource": "",
  "verb": "get",
  "name": "pod-one",
  "field_selector": ""
}
```

Scope is `namespaced`, `cluster`, or `unknown`. Namespaced queries require
a namespace; cluster queries require an empty namespace. The caller supplies
the resource scope and principal groups. The module does not discover them,
authenticate the principal, infer service-account groups, or check a token.
Conflicting known scope declarations for the same API group/resource are
rejected. Query identifiers are unique and request attributes are explicit,
not wildcards. Only sanitized inert inputs should be supplied: results embed
the inputs and do not redact annotations or other supplied text.

## Pinned semantics and deliberately unsupported cases

The semantic profile is
`kubernetes-v1.34.0-resource-rbac-subset-v1`, inspected against official
documentation and the tagged upstream implementation. It is not a claim of
complete Kubernetes version coverage.

- Grants are additive. The module accepts no invented deny rule.
- A RoleBinding references a Role in its own namespace, or confines a
  ClusterRole grant to that namespace. ClusterRoleBindings reference only
  ClusterRoles.
- Users and supplied groups match exactly and case-sensitively. A
  ServiceAccount matches `system:serviceaccount:<namespace>:<name>`; an omitted
  subject namespace defaults only from a RoleBinding's namespace. A
  ClusterRoleBinding ServiceAccount subject needs an explicit namespace.
- User/Group subjects require `rbac.authorization.k8s.io`; ServiceAccount
  subjects require the empty API group. Role references require the RBAC group.
- Verbs and API groups match exactly or `*`. The core API group is `""`.
  Resource matching supports exact `resource/subresource`, `*`, and
  `*/subresource`. It does not use generic glob matching: `pods/*` does not
  match `pods/log` in this pinned matcher.
- Nonempty `resourceNames` restrict to an exact authorization name; an empty
  list is unrestricted and a literal `*` is not a name wildcard.
- Top-level create and collection queries require an empty name. This
  prevents a submitted future object name from inventing a named create or
  deletecollection grant. Subresource create can use its explicit parent name.
- List/watch queries without selectors use an empty authorization name.
  Any nonempty field selector is explicitly inconclusive, including
  `metadata.name=...`. This component does not parse selectors or reproduce
  request-name derivation from an HTTP request.
- ClusterRole aggregation is unresolved. Supplied materialized rules on an
  aggregated role are not used as known grants. Missing role references and
  aggregation produce source issues; no controller is simulated.
- Valid non-resource URL rules on ClusterRoles cannot grant these resource
  queries. Non-resource requests are outside the input contract.

Official primary sources:

- [Kubernetes RBAC documentation](https://v1-34.docs.kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [Resource rule matcher](https://github.com/kubernetes/kubernetes/blob/v1.34.0/plugin/pkg/auth/authorizer/rbac/rbac.go)
- [Verb, API group, resource and name helpers](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/v1/evaluation_helpers.go)
- [Role resolution and subject matching](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/registry/rbac/validation/rule.go)
- [RBAC validation constraints](https://github.com/kubernetes/kubernetes/blob/v1.34.0/pkg/apis/rbac/validation/validation.go)

## Results, replay and uncertainty

Each sorted query result is one of `allow_in_supplied_model`,
`no_matching_allow_in_supplied_model`, or `inconclusive`. A known grant has
sorted binding/role/rule-digest/subject witnesses. Every source issue is
reported conservatively across queries. A known additive grant can remain
an allow alongside explicit unresolved-source uncertainty. One deterministic
matching subject is retained per binding/rule witness, not every equivalent
subject match. Without a known
grant, unresolved sources, unknown scope, or unsupported selectors yield
inconclusive, not a clean negative.

No matching allow is not effective cluster denial. Other authorizers,
authentication, admission, special privileged groups, implicit defaults,
live configuration, and snapshot completeness are not evaluated. A modeled
allow is not proof of request success, an exploit, or a finding of policy
violation without an independently supplied expected-access policy.

The frozen record owns canonical JSON text. `to_dict()` returns a detached
document; `to_json()` returns canonical text. Every parser and export repeats
algorithm replay over the embedded sources. `from_dict()` and native-byte
`from_json()` reject false results even when their outer hash is coherently
recomputed. The explicit verifier also requires the separately supplied
snapshot and queries to match exactly. An unsigned, coherently changed
snapshot with correctly recomputed results can describe another model; it
does not authenticate that model or bind it to the original sources.

Snapshot, query-list, per-query, rule and analysis digests use separate
`sunderkey.kubernetes-rbac-*.v1` domains. These are canonical parsed-content
addresses, not raw wire-byte provenance. Whitespace and JSON object-key order
can parse to identical content. Array order remains bound. Reordered object,
binding-subject, role-rule, and query lists preserve deterministic reasoning
where their semantics are equivalent, while truthful source/query addresses
change. A supplied raw-byte spelling is not retained or certified.

## Bounds and acceptance evidence

Intake accepts only bounded native dict/list/str/int/bool/null trees, with
signed64 integers and no floats, nonfinite values, cycles, aliases with
custom container types, or invalid UTF-8 strings. Shared subtrees are charged
at every occurrence. Native capture budgets precede hashing and replay.
Byte intake has a 4 MiB limit and checks nesting before JSON decoding; it
rejects duplicate keys at all levels. Node and conservative escaped-byte
budgets apply to the owned decoded tree before semantic processing.

Bounds are 24 levels, 100,000 nodes, 4,096 characters per JSON string,
256 objects, 128 queries, 128 values/rules/subjects per local list,
2,048 total rules, 4,096 total subjects, 2,000,000 matching work units,
and 2,048 total witnesses. Matching work charges repeated binding references
to a role and each rule's matching-list lengths. Limits are rejection bounds,
not truncation targets. Output also must fit the native tree budgets.

Synthetic tests cover scope confinement, subjects, exact rule semantics,
name and selector restrictions, adverse/unknown inputs, additive witnesses,
aggregation, ambiguity, deterministic ordering, detached output, byte parsing,
boundedness, and coherent result/source replay. They provide software
evidence only. Containment, signed runtime provenance, commander readiness,
independent Control/Assurance qualification, routing, and deployment remain
separate gates. Every record preserves `none` effects for qualification,
routing, execution, deployment, and target interaction.

The analyzer captures caller inputs before reasoning, with no callback inside
capture. It does not certify arbitrary in-process code, concurrent caller
mutations, valid substitutions made before entry, or authenticated source
origin. Its digests prove only the declared canonical content and replay.
