# Offline Vehicle Gateway Graph Projection

This R0 partial component compares caller-supplied interface flows with a
caller-supplied vehicle segment and gateway graph. A projected allowance exists
only when an explicit channel rule matches the flow's directed source and
destination segments. Cross-segment rules must refer to a declared gateway
bridge with the same direction. Same-segment flows also require an explicit
rule. A mismatch is an unsigned, nonqualifying candidate about the supplied
model, not a security finding or evidence of actual vehicle behavior.

The narrow segmentation and gateway-review use case is informed by
[NHTSA's 2022 Cybersecurity Best Practices for the Safety of Modern Vehicles](https://www.nhtsa.gov/sites/nhtsa.gov/files/2022-09/cybersecurity-best-practices-safety-modern-vehicles-2022-tag.pdf),
which discusses network segmentation and gateway boundary controls. This
component does not implement or verify those controls. It never contacts a
vehicle, telematics service, gateway, or other network, and it cannot apply a
policy, route a message, or control a physical function.

The closed JSON model contains nodes, interfaces, directed gateways, explicit
allowed-flow rules, and expected flow dispositions. Each item is bounded and
validated before projection. An incomplete inventory returns `unknown` and
zero candidates, with no settled row projections or mismatch entries. To keep
the report bounded, each flow lists at most one matching rule ID and reports
the total match count plus a truncation flag. Verification independently replays the original model and
rejects altered reports or a changed source. The report records all operational
effects as `none` and cannot authorize, publish, or qualify any result.
