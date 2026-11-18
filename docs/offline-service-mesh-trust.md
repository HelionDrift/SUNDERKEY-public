# Supplied service-mesh trust projection

This R0 component belongs to profile `AOE-GB-D06-S08`, capability
`army.gb.d06.s08`, vector `AV-GB-D06-S08-01`, package
`IWP2-AOE-GB-D06-S08`, and wave `IW2-015`. Its component ID is
`api_supplied_service_mesh_trust_projection`. It contributes partial A7.4
evidence only and does not complete or qualify the specialist.

The schema version 1 model supplies named workloads with declared identities
and sidecar presence, service routes and destination references, route policy
references, mTLS and identity policies, and synthetic flow outcomes. All
identities are literal. There is no Kubernetes, service-discovery or mesh
lookup. A route declares one destination and one policy; the model does not
resolve real traffic routing or sidecar deployment.
An `unknown` workload identity is rejected rather than treated as a concrete
identity. An unknown presented identity on an mTLS flow produces uncertainty.

Only complete `strict` mTLS policy, complete source and destination sidecars,
declared `via_sidecar` paths, known transport, and complete flow observations
support a decision. Plaintext is expected to be denied under those premises.
For mTLS, the caller must declare complete identity binding and a presented
identity exactly matching the declared source workload identity. The policy
then uses an exact identity allowlist or explicit `allow_any` rule. A supplied
allowed outcome that contradicts an expected deny is a candidate. A supplied
denied outcome that contradicts expected allow is a separate availability
contradiction, not a security-bypass candidate. Matching outcomes remain
declaration-level matches, not verified security findings.

Permissive or disabled mTLS, absent/incomplete sidecars, bypassed or unknown
paths, incomplete routes/policies, mismatched presented identity, uncertain
binding or observations produce `unknown`. The component intentionally does
not infer vulnerability from absent sidecars or permissive mode alone because
ambient or other enforcement may apply. It does not model certificate
validation, identity issuance, protocol negotiation, traffic splits, endpoint
selection, retries, rewrites or actual policy enforcement.

`analyze_supplied_service_mesh_trust` accepts a native model;
`analyze_supplied_service_mesh_trust_bytes` accepts bounded ASCII JSON bytes.
`verify_supplied_service_mesh_trust_analysis` rederives a report against a
separately supplied original model. `from_json` validates internal derivation
from the report's embedded source, but it alone cannot establish that the
embedded source is the separately approved original. Reports include the
source model, domain-separated source and report addresses, bounds,
limitations, false verification flags and `none` effects. The synthetic R0
request is `examples/offline-service-mesh-trust-component.json`.

This leaf makes no Kubernetes, cloud, network, process or credential call. It
does not claim observed traffic, validated mTLS, live exploitability,
authority, qualification or positive use.
