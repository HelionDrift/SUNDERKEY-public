# Capacity and economics contracts

This increment defines an immutable evidence boundary for capacity planning and
assessment economics. It supports roadmap packages S6.8 and P5.10 without
claiming that live metrics, provider quota APIs, billing systems, or production
infrastructure exist.

## Contract records

`MeasurementWindow` binds one closed time interval to all required dimensions:
tenant, assessment, provider, region, and worker pool. Each window contains:

- worker capacity and busy time in milliseconds;
- one queue-time sample in milliseconds for every request;
- request, input-token, and output-token counts;
- model, tool, and storage costs in micro-US dollars;
- storage start and end values in bytes; and
- the count of independently validated findings.

Duration, worker utilization, queue p50 and p95, storage growth, and total cost
are derived and revalidated during parsing. Queue percentiles use the
deterministic nearest-rank method. Content addresses cover the source values,
dimensions, provenance, and custody references.

`CostAttribution` groups complete measurement windows by tenant and assessment.
Every window must appear in exactly one attribution. Request, token, storage,
finding, and cost totals must equal the sums of the referenced windows. This
prevents cross-tenant attribution and double counting. Total cost and cost per
validated finding are derived. Cost per validated finding is null when there
are no validated findings.

`ProviderQuotaSnapshot` carries the five required quota dimensions:

| Quota | Exact unit |
| --- | --- |
| concurrent requests | requests |
| daily cost | microusd |
| input tokens per minute | tokens |
| output tokens per minute | tokens |
| requests per minute | requests |

Limit, used, reserved, headroom, and headroom basis points are explicit or
derived. Used plus reserved cannot exceed the limit. A snapshot has an
observation time, expiration time, source hashes, provenance, and optional
custody references.

`DemandForecast` uses the same five names and exact units as provider quotas.
Each metric contains lower, expected, and upper demand, with the expected value
inside the bounds. The forecast binds its source measurement windows and source
hashes, declares a bounded horizon, and states confidence in basis points.
Source measurements must match the provider and region and must exist before
forecast creation.

`CapacityPolicy` sets maximum evidence ages, maximum forecast horizon, minimum
confidence and quota headroom, maximum worker utilization and queue p95, and
assessment and validated-finding cost ceilings.

`AdmissionRecommendation` is derived for one tenant, assessment, provider, and
region. It is an advisory record. An admit disposition is possible only when no
blockers exist. A deny disposition names every deterministic blocker found by
the policy evaluation.

## Fail-closed rules

The implementation rejects:

- negative values, booleans used as integers, unknown fields, and invalid IDs;
- missing required dimensions or incomplete quota and forecast metric sets;
- mixed or incorrect units;
- invalid timestamps and zero-length or reversed windows;
- overlapping measurement windows for identical dimensions;
- queue samples that do not cover every request;
- worker busy time above declared capacity;
- decreasing storage counters presented as growth;
- quota oversubscription;
- forecast bounds that do not contain expected demand;
- forecast sources with mismatched provider or region;
- forecasts created before their measurement evidence;
- attribution totals that are not derived from their source windows;
- windows attributed twice or left unattributed;
- stale, future, expired, or horizon-mismatched evidence at admission time; and
- measured production claims without custody references.

Stale evidence, insufficient headroom or confidence, forecast demand above
quota headroom, excessive utilization or queue time, and excessive assessment
economics produce a deny recommendation. They never produce implicit runtime
authorization.

## Provenance and custody

Evidence provenance is one of `synthetic`, `measured_test`, or
`measured_production`. A `measured_production` window or quota snapshot requires
at least one opaque `custodyref:` value. Source evidence is referenced only by
SHA-256 content address. The contract contains no secrets or provider account
identifiers beyond opaque references.

## Deliberate boundary

This module performs no metric collection, provider request, pricing lookup,
billing, persistence, scheduling, authorization, worker control, scaling, or
qualification. Caller-supplied time is mandatory, so evaluating the same
inputs produces the same record. Production completion still requires metric
collectors, billing and quota integrations, durable storage, alerting, capacity
automation, operational ownership, and controlled canary evidence.

The strict JSON Schema is
`registry/schemas/capacity-economics-contract-v1.schema.json`.
