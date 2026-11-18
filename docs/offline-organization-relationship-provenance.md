# Supplied Organization Relationship Provenance Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D01-S09`, capability `army.ga.d01.s09`, vector
`AV-GA-D01-S09-01`, work package `IWP2-AOE-GA-D01-S09`, and wave `IW2-009`.
The domain commander is `AOE-GA-D01-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts only synthetic subject, organization, source, and
record labels. It compares caller-declared relationship states using a
caller-declared logical current tick and maximum age. A later fresh claim
from the same source supersedes its older claim. Fresh contradictory current
and former claims are a review candidate, not proof of a real relationship.
Distinct source references are not independent verification. Stale-only or
incomplete claims remain unknown.

The model accepts no names, contact details, titles, profile URLs, message
content, or real identifiers. It does not build a social-engineering path or
infer access. `analyze_supplied_organization_relationships` emits an unsigned
content-addressed report. Verification replays a separately retained
original model through `verify_supplied_organization_relationships` or its
bounded JSON-byte variant. The embedded model cannot authenticate itself.
A synthetic dispatcher input is in
[the component example](../examples/offline-organization-relationship-component.json).

No public collection, account lookup, message, target interaction, finding
publication, positive use, or qualification occurs.
