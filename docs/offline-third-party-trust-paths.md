# Supplied Third-Party Trust Paths

The `AOE-GA-D04-S17` partial specialist compares caller-supplied MSP or third-party authority-path claims with caller-supplied directed trust-edge declarations. The component is a local consistency check, not an attempt to traverse a relationship or compromise a provider. It contributes partial A7.4 offline evidence only.

The registered ownership is capability `army.ga.d04.s17`, vector `AV-GA-D04-S17-01`, implementation package `IWP2-AOE-GA-D04-S17`, wave `IW2-001`, commander `AOE-GA-D04-CMD`, and independent validator `AOE-HQ-19`. Its blueprint is `sha256:3e14f4bfab98a997fa26556587145abf64d3de3c324172bea9fac8a3b2770ed9`.

## Supplied Model

An exact native JSON object declares a source ID, an inventory-complete Boolean, at most 64 party nodes, at most 128 directed relationship edges, and at most 64 declared authority paths. Party kinds are `first_party`, `msp`, and `third_party`. A path must start at an MSP or third-party node, follow one to 16 known directed edges, and end at a first-party node. Edges have an enabled flag and an authority state of `authorized`, `denied`, or `unknown`. Each path provides a Boolean `claimed_authorized` and `context_complete`.

For a complete inventory and complete path context with no unknown edge authority, the projection computes whether every edge is enabled and authorized. It compares that result with the path claim. A disagreement is a candidate *supplied-declaration mismatch*, not evidence of actual access. An incomplete inventory, incomplete path context, or unknown edge authority yields `unknown`, with no candidate. Structurally disconnected, duplicate, or unsupported paths are rejected rather than interpreted as findings.

## Boundaries and Replay

The model is limited to 65,536 canonical bytes and the report to 131,072 bytes. Native JSON tree, string, identifier, list, and path-length bounds apply. The report carries its supplied premises and a digest, but neither authenticates its source. A separate original-model replay is required to compare a report or exported report bytes. The [synthetic example](../examples/offline-third-party-trust-paths-component.json) uses fictitious labels only.

Relationships, authority, path claims, and completeness remain unverified caller assertions. No actual compromise, lateral movement, authorization enforcement, or provider access is established. The component does not receive credentials, contact a target or MSP, invoke a process, publish a finding, grant positive use, or qualify a specialist. Every operational effect is `none`.
