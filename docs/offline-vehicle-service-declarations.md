# Offline Vehicle Service Declarations

This R0 partial component for `AOE-GD-D25-S03` compares caller-supplied service,
consumer and directed zone-route declarations. Its bounded local policy model
checks declared interface identifiers, major versions, minimum minor versions,
service enabled state and route permission against a caller-supplied
`claimed_allowed` value. A known disagreement becomes an unsigned review
candidate. Incomplete service or route inventories, or incomplete consumer
context, remain unknown.

The version threshold and route comparison are local policy conventions. This
component does not parse or validate a SOME/IP message, perform service
discovery, prove Automotive Ethernet configuration, or establish vehicle
reachability. It never contacts a vehicle, ECU, gateway, network or credential,
and never enacts a route or control action. Matching declarations do not prove
access or safety. The source ID and completeness flags are caller assertions,
not authenticated evidence.

The closed native JSON model accepts at most 32 zones, 64 services, 128 routes
and 64 consumers. Its deterministic report is replay-verifiable only against a
separately retained original model. All operational effects are `none`; the
report is not a finding, qualified specialist or approval for positive use.

Example: [`examples/offline-vehicle-service-declarations-component.json`](../examples/offline-vehicle-service-declarations-component.json).
