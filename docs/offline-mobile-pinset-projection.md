# Supplied Mobile Pinset Projection

The GB-D08-S09 partial component compares at most 32 declared synthetic
hostnames with 32 supplied pinsets and at most eight pins per set. It projects
exact or suffix-boundary hostname matches, declared expiry relative to a
caller-supplied evaluation day, and whether a pinset contains distinct,
nonexpired primary and backup pins. The report retains IDs and counts, not
hostnames or pin digests. Separate verification replays the original model.

These are deliberately defined model rules, not Android or iOS pinning
semantics. Fixture status, inventory completeness, expiry, and pin roles are
unverified assertions. A matched or unmatched host, an expired pin, or a
declared backup pair cannot prove a vulnerability, live trust, enforcement, or
safe rollover. No app is inspected, TLS handshake is made, pinning is bypassed,
or target is contacted. No finding, qualification, or action authority follows.

The checked synthetic example is
[`examples/offline-mobile-pinset-component.json`](../examples/offline-mobile-pinset-component.json).
