# Supplied Kubernetes Service/EndpointSlice consistency

This pure algorithm component compares a bounded, caller-supplied projection of
one ordinary ClusterIP Service, Running nonterminating Pods and controller-labelled
EndpointSlices. It neither acquires cluster objects nor calls Kubernetes. Sources,
UIDs, ownership, readiness and completeness are unauthenticated declarations. Even
`consistent_supplied_subset` does not establish controller behavior, routing,
connectivity, current health, effective access or specialist qualification.

## Ownership and public API

The component is `kubernetes_supplied_service_endpoint_consistency`, belonging to
AOE-GC-D15-S07, capability army.gc.d15.s07, vector AV-GC-D15-S07-01, work package
IWP2-AOE-GC-D15-S07 and wave IW2-009. Its source blueprint is
sha256:ae690f9ea176aeee2f7cc66d6a5f7d1837a81ebac3c8cdaed7421c470745d875.
Initial evidence is A7.4 only. All effects are `none` and all promotion claims are
false. The existing NetworkPolicy algorithm and profile default are not changed.

- `analyze_supplied_kubernetes_service_endpoints(model)` returns a frozen
  `KubernetesServiceAnalysis`.
- `analyze_supplied_kubernetes_service_endpoints_bytes(*, model_bytes)` accepts
  exact native bytes containing the bounded ASCII JSON projection.
- `component_fixture()` returns a fresh inert model using public leaf code only;
  it is not acquisition, controller evidence or an authenticated snapshot.
- `KubernetesServiceAnalysis.from_dict(document)` and `.from_json(document_json)`
  rederive the complete embedded model before accepting a canonical report.
- `.to_dict()` and `.to_json()` revalidate that complete embedded-source replay.
- `verify_supplied_kubernetes_service_analysis(report, *, model)` additionally
  compares against a separately supplied original projection. A valid alternate
  embedded model is not proof of the original source.

The report uses `analysis_id`, `analysis_sha256`, `source_model` and
`source_model_sha256`. Canonical JSON preserves array order and exact native
values; object keys are sorted. The model address binds the parsed canonical
projection, not the original input JSON bytes or acquisition provenance. Report
JSON is canonical. Self-addressing is not authentication, custody or authority.

## Exact closed projection

The root contains only `schema_version: 1`, `service`, `pods`, `endpoint_slices`,
`coverage` and `unsupported_features`. These are explicitly documented
projections, not unrestricted Kubernetes resource JSON or an API validator.

`service` requires namespace, name, UID, `type: "ClusterIP"`, canonical
`cluster_ip`, one `ip_family` (`IPv4` or `IPv6`), a nonempty equality `selector`,
`ports` and native boolean `publish_not_ready_addresses`. A Service port requires
name, protocol, port and `target_port`. Numeric targets need no container-port
declaration. Named targets use the protocol and named ordinary-container ports
of each selected Pod. There must be exactly one match; missing or multiple matches
remain unresolved. Iteration order never selects a winner.

A Pod requires namespace, name, UID, labels, `phase: "Running"`,
`terminating: false`, canonical single-family `ip` or null, native boolean `ready`
or null, and `container_ports`. Each ordinary-container port requires name,
protocol and numeric port. Namespaces and all equality-selector labels constrain
selection. A null Ready/IP projection means unavailable source information, not
healthy state or a predicted controller omission.

An EndpointSlice requires namespace, name, UID, address type, `service_name`,
`managed_by`, owner, ports and endpoints. The owner requires API version, kind,
name, UID and native controller boolean. Only the exact supplied Service identity,
same namespace, family, service-name label and managed-by value
`endpointslice-controller.k8s.io` join the supported source. Ownership or family
substitution is retained as uncertainty, not silently ignored as clean evidence.
Slice ports have explicit name, protocol and numeric port; no all-ports/null-port
semantics are inferred. Each endpoint has exactly one canonical address,
`target_ref` (kind, namespace, name, UID) and conditions (ready, serving,
terminating). Conditions accept native boolean or null; null remains unresolved.

`coverage` requires native `pods_complete` and `endpoint_slices_complete`
booleans. True permits arithmetic over the asserted inventory, not verified
completeness. False withholds coverage-dependent missing/extra conclusions.
`unsupported_features` is a distinct list drawn from sidecars, topology,
dual_stack, service_mesh, host_networking,
nondefault_controller_configuration and additional_unprojected_semantics.
Any declaration makes overall consistency inconclusive; known tuple observations
may remain. Missing or unknown fields are rejected, not normalized.

## Relational mathematics and results

For each selected Pod, the analyzer derives the Service port name, protocol and
resolved target number together with that Pod's exact namespace/name/UID/address.
Nonterminating expected conditions are `serving = supplied Pod Ready`,
`terminating = false`, and `ready = publishNotReadyAddresses OR serving`.
Publishing unready addresses never turns `serving` or health into true.

Each joined slice's port vector applies to each of its endpoints. Exact
identical expanded tuples across slices are deduplicated, while repeated
observations still consume work. Conflicting identity/condition observations for
the same address/port are retained and make the result inconclusive. A declared
Pod address shared by different identities is also unresolved. Source-reference,
UID and address joins are exact, not name-only.

The report retains sorted selected Pods, expected and observed endpoint tuples,
uncertainties, contradictions and coverage-dependent missing/extra sets. With
unresolved information, those missing/extra sets are withheld. Fully declared
contradictory conditions, nonselected known sources, wrong addresses or target
numbers remain explicit supplied contradictions. Status is one of
`consistent_supplied_subset`, `inconsistent_supplied_subset`, or `inconclusive`.
Known contradictions can coexist with uncertainty; the latter wins the overall
status. An empty fully declared model can be consistent without claiming a
healthy backend exists. Source list permutations preserve arithmetic, but retain
different canonical source identities and source-path diagnostics.

Excluded or unassessed: selectorless/manual/headless/ExternalName Services,
terminating or non-Running Pods, sidecars, topology, dual-stack, meshes, host
networking, controller packing/reconciliation/timing, kube-proxy, Service routing,
NAT, network-policy enforcement, availability and actual cluster readiness.
Canonical IPs and the declared grammar are narrower than Kubernetes accepts;
irregular IP spellings, unspecified/loopback/multicast addresses, relaxed Service
names and unknown fields are closed-subset rejections, not vulnerability findings.

## Finite software boundaries

Model/report JSON ceilings are 1/2 MiB, native nodes 32,768/65,536 and native
depths 20/24 (root depth one). Strings are printable ASCII with at most 512
characters; escape costs are counted. Native JSON containers and primitives must
have exact native types; floats, nonfinite values, boolean integer aliases,
subclasses, cycles and duplicate raw object members are rejected. Raw strings,
scalar depth, lexical nodes and signed 64-bit integer spelling are checked before
decoder or integer conversion. Repeated/shared native subtrees are charged for
every occurrence before copying them.

There are at most 128 Pods, 64 slices, 32 Service/slice ports, 64 ordinary-container
ports per Pod and 32 labels per map. At most 256 endpoints and 4,096 expanded
observed tuples are accepted; expected tuples also have a 4,096 ceiling. Each
issue kind has a 2,048-record ceiling. Retained rows charge aggregate bytes/nodes
before append. The complete report, including fixed-width addresses, must fit
before source or result hashing. Every public operation has a cumulative
33,554,432-unit work ceiling, including source capture, joins, retained output,
replay, serialization, comparison and hashing. Semantic planning constructs no
addresses. Each public operation funds every required derivative plan and final
comparison before materializing either source or result digest; separately
supplied original verification funds both plans in one cumulative budget.
Software exhaustion is a domain error, not fabricated inconsistent cluster
behavior. The ceilings apply together;
not every combination of their individual maxima is promised to fit.

The frozen record prevents ordinary assignment, and each public boundary
rederives owned source/report data. This is not arbitrary Python isolation,
concurrent caller-memory protection, transient-restored-mutation detection or
authentication of source snapshots. There are no callbacks, clock samples, file
writes, sockets, subprocesses, providers, credentials or automatic retries.

## Semantics and tests

The mathematical subset is independently written against the official
[Kubernetes v1.34 Service documentation](https://v1-34.docs.kubernetes.io/docs/concepts/services-networking/service/),
[v1.34 EndpointSlice documentation](https://v1-34.docs.kubernetes.io/docs/concepts/services-networking/endpoint-slices/)
and pinned
[Kubernetes v1.34.1 EndpointSlice utilities](https://github.com/kubernetes/kubernetes/blob/v1.34.1/staging/src/k8s.io/endpointslice/utils.go).
No upstream implementation is copied. The pinned utility distinguishes Ready and
Serving, numeric and protocol-specific named targets, Service owner identity,
per-slice port sets and per-family addresses. Its sidecar/irregular-IP behavior is
outside this closed projection. No claims cover future Kubernetes behavior.

The owned tests use fresh inert `component_fixture()` data, actual public parser
and verifier boundaries, a separately derived label/namespace/port oracle,
ready/serving and duplicate/conflict controls, full original-source substitution,
coherently readdressed false results and true prehash budget-denial observations.
No cluster, engine, secret, key or live endpoint is used.
