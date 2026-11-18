# Supplied Kubernetes API Authentication Context

This inert R0 component covers profile `AOE-GC-D15-S03`, capability
`army.gc.d15.s03`, vector `AV-GC-D15-S03-01`, package
`IWP2-AOE-GC-D15-S03`, and wave `IW2-005`. Its component ID is
`kubernetes_supplied_api_authentication_context`. It provides only partial
source-declaration evidence and does not qualify the specialist.

Schema version 1 accepts a bounded, closed model with `source_id`,
`inventory_complete`, sorted credential metadata references, and sorted
synthetic API request declarations. Credential metadata is limited to a
reference ID, service-account-token or client-certificate kind, declared
principal ID, optional token audience ID, declared validity, and completeness.
Requests declare a credential reference, expected principal, optional
audience, supplied outcome, and context and observation completeness. The
model accepts no token bytes, private keys, certificate bytes, kubeconfig,
headers, or authentication exchanges. IDs are bounded symbolic references,
not credential material.

With a complete inventory and request context, only declared expired validity
supplies an expected rejection. A contrary supplied `authenticated` outcome
becomes a `candidate_declared_authentication_mismatch`, not an observed bypass.
Principal differences are identity expectation mismatches, not authentication
failures. A single declared token audience and API audience cannot prove that
their full accepted sets are disjoint. Both differences remain `unknown` with
null expected authentication. Missing references, unknown validity, incomplete
metadata, context, observation, or inventory also remain `unknown`. A matching
declaration does not establish actual API authentication.

`analyze_supplied_kubernetes_api_authentication` accepts a native model;
`analyze_supplied_kubernetes_api_authentication_bytes` accepts bounded JSON
bytes. `verify_supplied_kubernetes_api_authentication` requires the exact
native report class and separately supplied original model;
`verify_supplied_kubernetes_api_authentication_bytes` validates an exported
report against the same original. Reports carry a domain-separated address,
false verification flags, limitations, and `none` operational effects. The
synthetic example is
`examples/offline-kubernetes-api-authentication-component.json`.

No Kubernetes API, credential provider, network, process, or target is
contacted. No credential is tested, and no authority, finding, positive use,
or qualification is established.
