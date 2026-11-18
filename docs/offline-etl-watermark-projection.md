# Supplied ETL watermark projection

The `AOE-GB-D07-S11` partial specialist projects explicitly supplied ETL step
dependencies and abstract output watermark ticks. It rejects cycles and
undeclared steps. For each objective, it collects declared upstream lineage,
lists incomplete steps, and compares the minimum declared watermark to the
requested threshold.

The exact native JSON model uses `schema_version: 1`,
`semantics_profile: supplied-etl-watermarks-v1`, 1 to 128 opaque step digests,
up to 256 dependency edges, and 1 to 16 objectives. Complete steps must have
an integer watermark; pending and failed steps cannot claim one. Native type
and byte bounds apply. The typed report replays from its supplied model.

Step state, lineage, and watermark are unauthenticated caller declarations.
A complete supplied lineage does not prove pipeline execution, data freshness,
or a working data product. No pipeline, notebook, provider, credential,
network, or target is contacted. The report grants no action authority or
qualification. The [synthetic example](../examples/offline-etl-watermark-component.json)
uses only fictitious opaque references.
