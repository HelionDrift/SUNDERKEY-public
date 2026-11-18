# Offline Synthetic Blast Radius Review

This V9.7 component reviews caller-supplied, synthetic impact-path evidence. It
reuses the exact tenant, scope, scenario, synthetic principal, surface, and time
window from [synthetic scenario consent screening](synthetic-scenario-consent.md).
It produces a historical, nonqualifying review. It cannot deliver phishing
messages, create accounts, collect credentials, access a target, or approve a
scenario. The consent record and every evidence digest remain caller assertions.

## Input Contract

`build_synthetic_blast_radius_review` accepts one typed request and one typed
consent. It recomputes the consent-screening plan at `planned_at` and requires a
human-review candidate. This is a consistency check, not authentication or
execution authority. `review_at` must follow planning.

The graph has one seed equal to the approved opaque synthetic principal and at
most 64 canonical nodes and 256 canonical directed edges. Every non-seed node
must be an opaque synthetic-resource reference. Node classes distinguish a
service, data canary, and recovery canary. Edges record an exact boundary kind,
boundary digest, asserted outcome, event time, and evidence digest. Event times
must fall within the consented window, after planning, and before review.
Blocked or unknown edges do not extend reachability. A bounded graph traversal
returns one deterministic, shortest declared path per reachable impact node.
It does not infer unlisted paths or prove that any edge was actually traversed.

Closure metadata separately records cleanup and disclosure as pending or
declared complete, with times and evidence digests. A custody digest identifies
an asserted source record. The review reports whether those obligations are
still due but always marks cleanup, disclosure, custody, consent, and path
outcomes as unverified. Report hashes bind all supplied metadata, and
`verify_synthetic_blast_radius_review` reproduces the report from the same
sources. Replay integrity does not authenticate the sources.

## Operating Boundary

Only synthetic fixtures belong in this contract. Do not include an employee
address, live account, reusable credential, URL, payload, or sensitive data in
node references or evidence fields. The graph's result is a declared scenario
model, not a penetration-test finding or measured business impact. Independent
review must inspect consent provenance, population assurance, exact scope,
activity traces, cleanup, disclosure, and evidence custody before any wider
claim. All authority, delivery, execution, network, and target-interaction
effects remain `none`.

Authenticated consent, ephemeral synthetic identities, approved simulation
integration, qualified internal runners, stop controls, current telemetry,
cleanup proof, and independent review remain outside this offline component.
The report schema is
[`synthetic-blast-radius-review-v1.schema.json`](../registry/schemas/synthetic-blast-radius-review-v1.schema.json).
