# Supplied Scan-Scope Projection

The GA-D01-S02 partial component compares at most 64 synthetic proposed
network prefixes against at most 32 caller-supplied scope CIDRs. It accepts
canonical IPv4 and IPv6 networks and lists proposals not wholly contained by
any supplied scope. Separate verification replays the original supplied model.

The supplied scope is not an authorization record. Proposal containment does
not permit scanning, and an outside-scope declaration is not evidence of
target interaction. The component does not resolve DNS, send packets, use a
scanner, contact a target, or publish a finding. It cannot grant authority or
qualify the specialist. A live scan would still require fresh scope, action
admission, and containment checks outside this offline projection.

The checked synthetic example is
[`examples/offline-scan-scope-component.json`](../examples/offline-scan-scope-component.json).
