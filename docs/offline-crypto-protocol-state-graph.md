# Supplied Cryptographic Protocol State Graph

The GE-D22-S01 component projects state reachability and the shortest
caller-declared acceptance path without a supplied peer-authentication marker.
It accepts at most 32 states and 128 transitions, with unique IDs and closed
state references. The graph may contain cycles.

Acceptance, authentication markers, and inventory completeness are assertions.
An unmarked graph path does not establish an authentication bypass, a real
protocol path, a finding, or permission to act. No packet, key, endpoint, or
target is observed.

The checked synthetic example is
[`examples/offline-crypto-protocol-state-component.json`](../examples/offline-crypto-protocol-state-component.json).
Verification requires replay against the separate original model.
