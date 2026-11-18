# Offline GCP sizing and recovery worksheet

This worksheet calculates prospective costs, declared headroom, and conditional
recovery timing from explicit operator inputs. It is not a price lookup, sizing
measurement, quota observation, billing hard cap, signed recovery objective,
backup manifest, or restoration result. It performs no cloud call, credential
access, metric collection, persistence, deployment, scaling, or target action.

## Sources and API

`build_gcp_sizing_recovery_worksheet` requires the complete input dictionary plus
an explicit `GcpResourceBindingPlan`, `ProductionDeploymentDecisionDossier`,
`DeploymentProfile`, and `TenantRegionBinding`. It composes
`verify_gcp_resource_binding_plan`, which revalidates the exact supplied source
records. The worksheet binds the resource plan and its three source identities
and SHA-256 values. It does not select D014 or authorize use of those resources.

`GcpSizingRecoveryWorksheet.from_dict` and `from_json` reconstruct the exact
arithmetic, closed fields, native types, content address, and effect labels.
Parsing a self-consistent content address is not source authentication.
`verify_gcp_sizing_recovery_worksheet` requires all four source inputs again,
checks exact bindings, and retains the resource plan's planning blockers.
Every returned dictionary is detached. No file loader or default source exists.

## Complete explicit input shape

All listed fields are required. Unknown quantities, individual rates, ceiling
limits, budget amounts, and recovery inputs must be supplied as `null`, not
omitted. Null remains a named blocker and never becomes an implicit zero.

The top-level fields are `as_of`, `horizon_start`, `horizon_end`, `currency`,
`quantities`, `rates`, `ceilings`, `budget`, and `recovery`. Times use whole-second
UTC ending in `Z`. The horizon starts at or after `as_of`, has positive duration,
and is at most 366 days. Version 1 supports explicit `USD` and `microusd`, matching
the existing capacity/economics contracts. It performs no currency conversion.

Quantities are `worker_count`, `worker_seconds_each`, `storage_bytes`,
`network_bytes`, `input_tokens`, `visible_output_tokens`, and `reasoning_tokens`.
Per-worker seconds cannot exceed the horizon. These are declared scenario
quantities, not observed usage. Input, visible-output, and reasoning token counts
must be disjoint. The worksheet cannot infer a provider's billing classification.

For OpenAI Responses usage, total output includes reasoning tokens and those
tokens are billed as output. Do not put inclusive `usage.output_tokens` into
`visible_output_tokens` and then add reasoning tokens again. The pure
`split_output_token_usage(total_output_tokens=..., reasoning_tokens=...)` helper
subtracts the explicit reasoning subset and rejects negative, aliased, overflow,
or inconsistent counts. It neither fetches usage nor chooses a price. For such a
billing model, supply the applicable output quote for both disjoint output
categories; their separate display does not imply a reasoning discount. See the
[OpenAI reasoning guide](https://developers.openai.com/api/docs/guides/reasoning#how-reasoning-works)
and [spending-controller discussion](https://developers.openai.com/cookbook/articles/per_run_spending_controller_responses_api#limits-and-other-costs).

Rates have exactly these categories and units:

| Category | Unit | Quantity used |
| --- | --- | --- |
| `fixed` | `fixed_horizon` | One explicit horizon |
| `workers` | `worker_second` | Workers multiplied by seconds per worker |
| `storage` | `storage_byte_horizon` | Declared stored bytes for the explicit horizon |
| `network` | `network_byte` | Declared transferred bytes |
| `input` | `input_token` | Declared input tokens |
| `visible_output` | `visible_output_token` | Declared visible-output tokens |
| `reasoning` | `reasoning_token` | Declared reasoning tokens |

Each non-null rate contains exactly `currency`, `unit`, `unit_quantity`,
`price_micros`, `as_of`, `provenance`, `source_ref`, `source_sha256`,
`horizon_start`, and `horizon_end`. Unit quantity is positive; price is a
nonnegative integer number of micro-US dollars for that many units. Rate
currency and horizon must match the worksheet. Rate `as_of` cannot be later
than worksheet `as_of`. The summary exposes rate age without claiming freshness.
Provenance is `operator_supplied_quote` or `synthetic_quote`; source references
are opaque printable ASCII and are never dereferenced. A source hash is a
declared reference, not proof that a quote exists, is authentic, or remains valid.

Storage rates must explicitly cover the entire chosen horizon. The worksheet
does not convert provider GB-month, GiB-hour, minimum-duration, tier, discount,
request, retrieval, tax, or backup charges. The operator must supply appropriately
scoped separate scenario costs; unsupported charges must not be hidden in an
unverified unit conversion. No sample test rate represents a real provider price.
Cache-write and cached-input classifications, hosted tools, service tiers,
discounts, credits, and taxes are not individually modelled or promised covered.
The seven categories are deliberately limited and require external quote and
coverage verification before use as a planning estimate.

Each category cost is rounded up once from the exact fraction
`quantity * price_micros / unit_quantity`. Arithmetic uses integers, including
exact wide intermediates; inputs and every reported quantity, cost, and sum are
bounded to nonnegative signed 64-bit values. Overflow fails, not saturates.
Known subtotal is labelled separately from estimated total. Total is null if any
cost is unknown, even when a missing rate accompanies an explicit zero quantity.

## Ceilings and protected reserves

`ceilings` contains `worker_count`, `storage_bytes`, `network_bytes`, and
`model_tokens`. Each contains exactly `unit` and `limit`; units are `workers`,
`bytes`, `bytes`, and `tokens`, respectively. Model tokens are the sum of the
three disjoint token quantities. These ceilings are operator declarations, not
verified provider quotas, worker capacity, or concurrency limits.

`budget` contains `currency`, `unit`, `horizon_start`, `horizon_end`,
`ceiling_micros`, `stop_reserve_micros`, `evidence_reserve_micros`, and
`recovery_reserve_micros`. Currency, unit, and horizon must match. All three
reserves are added to estimated cost before budget headroom is calculated.
Missing or zero reserves remain blockers. They do not prove that a provider
account actually protects or withholds that money.

Known comparisons expose planned use, declared limit, headroom, excess, and a
within-ceiling flag. Over-budget or over-capacity scenarios report explicit
excess and blockers. They do not enforce a cap or grant admission. Unknown
comparisons retain null values instead of reporting a pass.

## Conditional recovery arithmetic

`recovery` contains `candidate_region`, `rpo_seconds`, `rto_seconds`,
`checkpoint_interval_seconds`, `checkpoint_lag_seconds`, `restore_bytes`,
`restore_bytes_per_second`, and `startup_seconds`. RPO, RTO, checkpoint cadence,
and throughput are positive when known. Lag, bytes, and startup time may be zero.
The candidate is a region-form name only, not verified provider availability,
residency permission, fault-domain independence, or selected recovery location.
There is no primary-region fallback and no modification to the resource plan's
unselected recovery region.

The declared recovery-point model is checkpoint cadence plus checkpoint lag.
The declared restore model is rounded-up byte transfer time plus startup time.
These conditional calculations assume the operator's inputs; they do not prove
backup completion, sustained bandwidth, replay/apply duration, key availability,
event continuity, evidence custody, catalog recovery, or actual RPO/RTO. Include
all anticipated non-transfer work in the explicit startup allowance, and verify
the eventual model with external rehearsals rather than treating arithmetic as
an observed bound.

Measured `MeasurementWindow`, quota and forecast records remain in
`capacity_economics_contracts`. Signed `RecoveryObjective`, `BackupManifest`,
restoration plan/result, and readiness assessment remain in
`disaster_recovery_contracts`. This worksheet creates none of those records and
does not weaken their provenance, reviewer, or continuity requirements.
Permanent external blockers make those boundaries explicit even when every
prospective input is complete and every arithmetic comparison is within limits.
