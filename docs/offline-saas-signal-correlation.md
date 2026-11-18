# Supplied SaaS signal correlation

The `AOE-GA-D01-S06` partial component joins bounded caller-supplied SaaS
signals by exact canonical ASCII domain. It keeps IdP application, DNS alias,
expense vendor, egress domain, and managed catalog signal kinds distinct. A
domain with multiple different supplied kinds is labeled
`multiple_supplied_signal_kinds`; one kind is labeled
`single_supplied_signal_kind`. Exact domain text is compared with a separate
caller-supplied catalog list. A catalog miss is not called shadow IT.

The model has exact fields `schema_version: 1`,
`semantics_profile: supplied-saas-signal-correlation-v1`, `signals`, and
`catalog_domains`. It accepts one to 512 signals and at most 256 catalog
domains. Each signal has a unique `signal_id`, a supported `kind`, a canonical
ASCII `domain`, and `source_id`. Duplicate kind/domain/source observations
are refused. Subdomains are not inferred to match parent domains. The typed
report replays its source model and supports independent current-model
verification.

This is a supplied-data correlation, not actual SaaS discovery or a completed
specialist. Signal and catalog sources are not authenticated. It does not
establish domain ownership, SaaS use, unauthorized use, customer scope, or a
finding. No DNS query, IdP call, billing query, egress inspection, credential
use, target interaction, qualification, or publication occurs. The
[synthetic example](../examples/offline-saas-signal-component.json) contains
only fixture domains.
