# Offline runtime and report integrity

This increment hardens existing repository boundaries using deterministic
injected ports and genuine contract fixtures. It performs no network, provider,
target, cloud or deployment operation. It changes no qualification, activation,
action tier, authority source, D014 selection or MissionStore schema version.

## Exact resource selection

The [local API service](local-api-service.md) rechecks the requested resource
identifier as well as resource kind, tenant and context. This applies to a get,
mutation preconditions, committed results and idempotent replay. A repository
cannot substitute another valid same-context record while retaining the outer
request identity. Lists still use their existing page and cursor semantics.

The [operator console](operator-console-client.md) independently checks the
identifier for a get before accepting, rendering or caching a projection.
The defect tests use otherwise valid records and responses, not malformed
payloads rejected by another validator.

## Current authority at an injected call

The [HTTP](authorized-http-runtime.md) and
[browser](authorized-browser-runtime.md) boundaries repeat their pure signed
scope decision at the final pre-call clock observation. This covers scope or
assessment-window expiry during DNS, body, safety or budget preflight without
making another transport call or scope-budget allocation.
The browser boundary also refreshes safety after confirmed budget reservation,
before its final clock and scope decision. A new stop condition produces zero
driver calls and follows the existing zero-usage settlement contract; settlement
uncertainty remains explicit rather than claiming the reservation never existed.

The [target-session boundary](authorized-target-session-runtime.md) also checks
scope and credential-lease currentness before reservation and after confirmed
reservation. Safety and revocation are refreshed after reservation, and the
last pre-provider time observation follows those injected checks. A delayed
reservation cannot authorize authentication with expired or newly revoked
inputs. Initial revocation evidence is retained in the transcript; fresh
pre-provider and post-provider evidence occupy the existing receipt slots.

A denial after confirmed reservation carries that exact reservation even when
the provider was never called. Its one settlement attempt records
`rejected_before_authentication` with `provider_called=false`. Confirmed
settlement has a completion digest; failed or ambiguous settlement retains
`completion_failed` with no fabricated completion. Authentication attempts
remain zero and provider cleanup is not required. There is no automatic refund,
retry or release of the consumed use number.

The existing receipt fields, enums and hash domains remain in use. The target
session schema admits only these narrow zero-call combinations. A receipt does
not prove an injected store, clock, monitor, revocation checker or provider is
independently qualified. The boundary cannot make external state changes
atomic with the final observation or guarantee that a caller-supplied adapter
obeys its contract.

## Exact finding and report replay

[Finding lifecycle](finding-lifecycle.md) parsers and
[assessment report](assessment-reporting.md) parsers compare canonical JSON for
the full reconstructed document. Python equality alone can equate different
JSON types, so it is not sufficient for addressed-document replay.

Regression tests retain twelve prior identity hashes, prove that changed
canonical bytes differ, and reject schema aliases, derived finding versions,
coverage counters, basis points, nested records and wire-score substitutions.
Valid object ordering and canonical round trips still pass. Constructors retain
their documented normalization; parsing never silently normalizes a different
document under the old claimed identity.

These fixes strengthen integrity, not report authenticity or live finding
validation. Evidence-only, no-effect, retest-plan-only and independent-review
boundaries remain unchanged. Comparative superiority still requires qualified
deployments and preregistered, equal-condition measurements.
