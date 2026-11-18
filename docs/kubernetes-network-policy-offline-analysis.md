# Supplied Kubernetes NetworkPolicy flow analysis

`sunderkey.kubernetes_network_policy_analysis` is a pure finite algorithm over
sanitized native namespace, pod, NetworkPolicy and flow declarations. It has no
cluster client, CNI, network, provider, process, file, credential, signing,
callback or deployment operation. It does not fetch or apply policies.

## Existing ownership and partial scope

The component is `kubernetes_supplied_network_policy_flows`, profile
`AOE-GC-D15-S07`, capability `army.gc.d15.s07`, vector `AV-GC-D15-S07-01`,
package `IWP2-AOE-GC-D15-S07`, and wave `IW2-009`. Its commander is
`AOE-GC-D15-CMD`, group commander `AOE-HQ-05`, independent validator
`AOE-HQ-19`, and blueprint digest
`sha256:ae690f9ea176aeee2f7cc66d6a5f7d1837a81ebac3c8cdaed7421c470745d875`.

This is partial offline evidence under the D016 sequencing amendment, not a
complete candidate or a replacement for the six reference SDKs. Control-plane
and admission-policy collaborator handoffs remain separate. No status, live
entry, containment, routing, deployment or qualification gate is satisfied by
this component. Service mesh, ingress controller and runtime acquisition are
not implemented here.

## Exact supplied model and interfaces

```python
analyze_supplied_kubernetes_network_policy(model) -> KubernetesNetworkPolicyAnalysis
verify_supplied_kubernetes_network_policy_analysis(
    report, *, model
) -> KubernetesNetworkPolicyAnalysis
```

The model has exactly `schema_version` (native integer 1), `namespaces`, `pods`,
`network_policies` and `flows`. Namespace projections have `name` and `labels`.
Pod projections have `namespace`, `name`, `labels` and native boolean
`host_network`. All namespace labels are explicit. A supplied
`kubernetes.io/metadata.name` label must match that namespace's name, but an
absent label is never invented. Empty label values are supported.

Policies use `apiVersion: networking.k8s.io/v1`, `kind: NetworkPolicy`,
`metadata` with exactly `namespace` and `name`, and `spec` with only
`podSelector`, `policyTypes`, `ingress` and `egress`. These fields are optional
inside the spec. Unknown fields reject rather than being dropped. This is a
closed sanitized projection, not a general Kubernetes API object or YAML
parser, admission validator, migration or source-acquisition interface.

Each flow has exactly these fields:

```json
{
  "flow_id": "database",
  "source_pod": {"namespace": "front", "name": "client"},
  "destination_pod": {"namespace": "back", "name": "db"},
  "protocol": "TCP",
  "destination_port": 5432
}
```

Namespace names, pod and policy identities, and flow identifiers must be
unique. All policy and pod namespaces and flow pod references must resolve
within the supplied model. Names and labels use the documented ASCII subset
of Kubernetes DNS and label spelling. Duplicate identity objects reject even
when their bodies agree. Nothing asserts that this snapshot includes every
real policy, namespace or pod.

## Finite declared semantics

The pinned profile is `kubernetes-v1.34.1-pod-network-policy-subset-v1`.
This is finite mathematics, not copied upstream code or a universal Kubernetes
version claim. Label selectors support `matchLabels` and `matchExpressions`
with `In`, `NotIn`, `Exists` and `DoesNotExist`. All requirements are ANDed.
`NotIn` includes a missing key. In/NotIn values must be nonempty; existence
operators have no values. Empty and omitted policy pod selectors select all
supplied pods in that policy's namespace.
[Kubernetes labels and selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)

A peer's pod selector alone is confined to the policy's namespace. A namespace
selector alone selects all supplied pods in matching namespaces. Both in one
peer are ANDed; separate peer entries are ORed. An empty peer object rejects,
but an empty rule is meaningful. Empty or omitted peer and port lists are
unrestricted for that rule. Peer and port matches within a rule are ANDed.
Ports are numeric 1 through 65535; `endPort` is an inclusive compact range and
requires an explicit numeric `port`. Missing protocol defaults to TCP, and a
missing port matches all ports on that protocol. TCP, UDP and SCTP are modeled
declarations, not proof that a plugin supports them.
[NetworkPolicy API](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/)

Omitted or empty `policyTypes` defaults to Ingress, with Egress added only
when the egress rule list is nonempty. An omitted or empty egress list does not
add Egress by default. Explicit Egress with no rules isolates and has no allow
rule. The protocol and policy-type defaults and empty-peer refusal were checked
against the tagged source without copying it.
[Tagged v1.34.1 defaults](https://github.com/kubernetes/kubernetes/blob/v1.34.1/pkg/apis/networking/v1/defaults.go),
[Tagged v1.34.1 validation](https://github.com/kubernetes/kubernetes/blob/v1.34.1/pkg/apis/networking/validation/validation.go)

A direction is isolated when any supplied policy selects the focal pod and
applies to that direction. Allowed rules combine additively across policies:
a deny-all declaration does not override a separate matching allow rule.
A distinct pod-to-pod flow requires both source egress and destination ingress
allowance. With no applicable policy, that direction has no restriction in
this supplied policy model. Rules are evaluated only for supplied flows, not
every possible pod pair. Reply traffic and existing connections are not modeled.
[Kubernetes NetworkPolicy concepts](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

## Truthful uncertainty

Named ports, IP blocks and `host_network: true` are recognized but unsupported.
Any such declaration anywhere makes the entire report incomplete and every
flow unassessed, including declarations on unused pods or unselected policies.
This is a conservative software choice, not a claim that every unsupported
declaration affects every real flow. IP-block strings are captured as bounded
metadata, not validated or evaluated as CIDR mathematics. Named-port strings
are not resolved against containers. A named or absent port with `endPort`
is malformed and rejects, rather than claiming range support.

Same-pod flows are unassessed rather than incorrectly blocked; the documented
pod-local exception is outside this distinct-pod evaluator. Node traffic,
host networking, Services, DNAT/SNAT, external endpoints, CNI behavior, plugin
convergence, service meshes, TLS, L7 rules and existing connection behavior
are not evaluated. No server request or target address is generated.

Flow outcomes are `allowed_in_supplied_policy_model`,
`blocked_in_supplied_policy_model` or `unassessed`. Directional results retain
isolation, exact applicable policy references and one first peer/port witness
per matching rule. They do not claim actual reachability or effective denial.
No vulnerability verdict is derived without an independent expected-access
policy, and no such policy is invented here.

## Replay, ownership and costs

The exact owned `KubernetesNetworkPolicyAnalysis` has `to_dict`, `to_json`,
`from_dict` and native-text `from_json`. Its canonical report embeds the full
captured source model and binds source, policy and report digests with separate
domains. JSON object order and whitespace are not raw-wire provenance. Source
array order remains bound, while semantically equivalent policy/object/flow
permutations can preserve derived flow reasoning.

Intake replays every derived row, witness, isolation state, bound, limitation,
flag and effect. Coherently readdressed false results reject. A coherently
changed source with genuinely recomputed results is still unsigned metadata
for another model; the separate original-model verifier rejects that model
substitution. All exports and returned records are detached. No hash proves
source authenticity, issuance, currentness, CNI enforcement or permission.

Fixed local software ceilings are 1 MiB per model or report, depth 16,
32768 visited nodes, 512 printable ASCII bytes per string, signed63 integer
magnitude, 64 namespaces, 256 pods, 128 policies, 64 flows, 64 labels per
object, 64 expressions per selector, 64 values per expression, 512 total
rules, 64 peers and 64 ports per rule, 1000000 matching work units and 2048
matching-rule witnesses. These ceilings compose; count-bounded input can
still exceed the report's byte or node limit. Limits reject, never truncate.

Native capture charges structural punctuation, escaped strings and every
repeated subtree before copying, serialization or hashing. Subclasses,
float/integer and boolean/integer aliases, cycles, unknown fields, duplicate
JSON keys, oversized integers and unsupported strings reject. Raw report
byte, node, depth, string, escape and exact JSON integer spelling are checked
before decoding. Output and match/witness ceilings are checked before hashes.

Selectors are compiled once per supplied occurrence. Cached selector results
are keyed by that compiled selector and exact namespace or pod identity.
Matching work counts each policy/rule/peer/port visit and the selector's
requirements on its first evaluation per identity; cached results need no
repeated requirement traversal. This is a bound on those algorithmic units,
not a wall-clock deadline or total CPU instruction count. Numeric port ranges
stay compact and are never enumerated. Matching and witness ceilings apply to
each deterministic derivation or replay. Public construction and exports can
repeat that bounded derivation to validate the owned record.

All `snapshot_authenticated`, `snapshot_complete`, `cni_enforcement_proven`,
`reachability_proven`, `live_use_approved` and `qualification_claimed` flags
are false. Authority, target, execution, routing, qualification, deployment,
network, provider, credential and process effects are `none`. This code does
not sandbox arbitrary same-process code, detect valid substitutions before
entry, authenticate supplied labels or protect concurrent caller mutation.
Only sanitized inert inputs should be supplied; reports preserve their
metadata and do not redact secrets.

Synthetic tests use independent finite selector and directional truth tables,
additive deny/allow controls, defaults, peer conjunction/disjunction, numeric
range endpoints, unsupported cases, literal identities, source permutations,
native cost boundaries, detached outputs and coherently rehashed replay
denials. They are software evidence only, not cluster or qualified evidence.
