# Supplied Passive Source Freshness Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D01-S01`, capability `army.ga.d01.s01`, vector
`AV-GA-D01-S01-01`, work package `IWP2-AOE-GA-D01-S01`, and wave `IW2-001`.
The domain commander is `AOE-GA-D01-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts only synthetic asset, source, and observation
labels. It compares caller-declared presence and absence claims against a
caller-declared logical current tick and maximum age. Fresh contradictory
claims are candidate conflicts after later claims from the same source
supersede its older fresh claims. Claims from two source references are labeled
as multiple supplied sources, not independent corroboration. Assets with only
stale observations remain unknown. An incomplete policy or source set makes
every asset disposition unknown.

This component differs from technology-label and SaaS signal reconciliation:
it tracks generic asset claims and declared freshness without inferring a
technology or service category. No claim proves an owned asset, current
exposure, valid scope, or a finding.

`analyze_supplied_passive_sources` emits an unsigned content-addressed report.
Verification replays a separately retained original model through
`verify_supplied_passive_sources` or its bounded JSON-byte variant. The
embedded model cannot authenticate itself. A synthetic dispatcher input is
in [the component example](../examples/offline-passive-source-freshness-component.json).

No public index, repository, DNS service, provider, network endpoint, or
target is queried. No passive collection, active scan, finding publication,
positive use, or qualification occurs.
