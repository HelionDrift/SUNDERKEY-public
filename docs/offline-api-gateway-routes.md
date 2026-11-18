# Supplied API gateway route selection

This R0 partial component belongs to `AOE-GB-D06-S07`, capability
`army.gb.d06.s07`, vector `AV-GB-D06-S07-01`, and wave `IW2-014`.
It evaluates a finite caller-supplied route table against caller-supplied
request probes. It cannot observe a deployed gateway or verify an
authorization bypass.

The exact schema version 1 model binds separate route-table and probe source
IDs. Routes declare host, method, exact or literal-prefix path, priority,
backend reference, and authorization-policy reference. A fixed
priority-descending then declaration-order rule selects the first match;
normalization and rewrites must explicitly be `none`. The report records
selection, narrowly provable shadowing, and differences among declared policy
references. Different policy IDs are not an ordering of strength, proof of
policy application, or evidence of exploitable bypass. Literal prefix uses
byte-prefix matching, not segment-aware routing.

`analyze_supplied_api_gateway_routes` returns a report with embedded bounded
premises and source digests. `verify_supplied_api_gateway_routes` independently
replays a separately supplied model; the common verifier also rechecks the
original request and current catalog. The checked synthetic example is
`examples/offline-api-gateway-routes-component.json`. Every operational
effect, target interaction, qualification, and positive-use claim remains off.
