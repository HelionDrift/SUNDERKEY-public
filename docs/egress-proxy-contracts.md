# Egress Proxy Contracts

This Phase 165 increment defines the repository-only contract boundary for
roadmap package X1.6. It does not open sockets, resolve DNS names, forward
requests, or claim that a live proxy enforced a decision.

The policy is deny by default. Each permitted destination is an exact lowercase
DNS name and port with explicit methods, path prefixes, IP networks, TLS SPKI
pins, and request and response byte limits. Redirect following is prohibited.
IP literals cannot replace the policy hostname.

Every request binds to one tenant, mission, scope, worker, policy hash, DNS
resolution attestation hash, operation, body digest, and optional credential
lease. Admission fails closed for stale or mismatched policy, stale DNS
evidence, unexpected addresses, an unknown endpoint, an unapproved method or
path, excess size, or redirect following.

`EgressEnforcementObservation` records what a separately deployed proxy claims
to have observed. Validation compares that evidence with the admitted request,
address network, TLS pin, response limit, redirect behavior, and outcome. The
record is not itself proof that enforcement occurred.

Observation validation requires the exact request ID and digest declared by the
admission decision, the exact policy ID and digest shared by the request and
decision, and matching declared resolution-attestation IDs and digests. It does
not reevaluate admission, authenticate a DNS source, establish current authority,
or contact a target. A self-consistent observation cannot substitute a different
request or policy for the records to which its decision was bound.

## Remaining external proof

Production completion still requires a deployed fail-closed proxy, authenticated
DNS attestation source, enforced routing that workers cannot bypass, captured
TLS and byte-limit evidence, failure-injection tests, and independent review.
Those facts cannot be produced by repository-only unit tests.
