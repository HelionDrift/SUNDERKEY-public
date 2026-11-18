# Local API Service Runtime Core

The local API service module supplies a deterministic in-process product
service boundary for roadmap packages P5.1 through P5.9. It is a runtime core,
not a deployed API. It opens no socket, depends on no web framework, owns no
database, performs no network call, authenticates no principal, delivers no
webhook, and executes no mission.

## Product resources

The service exposes one consistent record model for:

- assets and their owners, environments, eligibility, and exclusions
- missions and validated lifecycle transitions
- findings, affected assets, evidence, severity, validation, and ownership
- evidence chains from action and authorization through result and cleanup
- reports derived from a content-addressed record set
- remediation guidance, developer evidence, retest, regression, and closure
- approval decisions and their evidence references
- component health observations
- operator projections for mission, coverage, workers, approvals, health,
  budgets, graph changes, and blockers
- content-addressed target-context bundles produced by the bounded offline
  intake boundary

Each successful mutation also creates an integration event in the same commit
command. The injected repository is responsible for atomically storing the
resource, immutable audit entry, idempotency result, and event. An external
dispatcher can later deliver that event to a signed webhook, ticketing system,
SIEM, or case manager. The service itself never delivers it.

## Request control path

Every request carries an authenticated access context supplied by its caller.
The service sends an exact tenant, context, principal, session, request digest,
permission, and timestamp binding to the injected authorizer. A denied,
expired, or rebound decision fails closed.

Every mutation additionally requires an idempotency key and an exact admission
decision from the injected mutation admission port. Admission binds:

- the request and idempotency digests
- the authorization decision
- tenant, context, and principal
- operation, resource kind, and resource identifier
- the expected concurrency token
- an immutable admission audit reference and expiration

No mutation reaches the repository if any field is absent, stale, denied,
expired, or rebound.

## Consistency model

Resources have a monotonically increasing version and content-derived
concurrency token. Creates reject an existing record. Updates require the
current token. Finding and health operations support create or token-checked
update. Mission transitions follow a closed state graph. The repository must
check the expected token again during its atomic commit to close the gap
between read and write.

Audit references are append-only. A later resource version must retain the
entire prior audit chain and append exactly one new reference. The resulting
record, audit entry, and integration event bind to the same mutation.
Idempotent retries return the original result without adding another commit.
Reuse of an idempotency key for a different request fails closed at the
repository boundary.

Returned commit evidence must reproduce the resource, audit and event joins,
including their identities, original request payload and timestamp. Newly
committed results retain the exact constructed commit evidence. Replay retains
the original snapshot and historical decision references while still requiring
fresh authorization and admission; it does not compare those old references to
new ones. See [offline contract and API integrity](offline-contract-api-integrity.md)
for the bounded corruption and compatibility controls.

Target-context attachment is create-only. Its resource identifier must equal
the verified bundle identifier, and its payload must contain exactly one
bundle that passes the complete `TargetContextBundle` validator. The separate
attachment facade accepts bounded caller bytes, builds the bundle in memory,
and sends only that bundle through this service.

## Reads and pagination

Reads are authorized and scoped by tenant and context. Repository results are
rechecked before they are returned. A request naming one resource additionally
requires that exact resource identifier on every returned record, including an
idempotent mutation replay. A valid same-context record for another identifier
is not a substitute. Lists retain their separate ordering and cursor contract.
Lists require strict resource identifier
ordering and use a bounded page size of 100. A canonical cursor binds the last
identifier to the resource kind, tenant, and context. Its digest detects
accidental or malicious editing. The cursor is not an authorization token and
is never accepted without a fresh authorization decision.

## Roadmap coverage

| Package | Repository capability in this increment | Infrastructure still required |
| --- | --- | --- |
| P5.1 | Asset create, update, get, and list boundary | Durable store and deployed access endpoint |
| P5.2 | Mission create and lifecycle transition core | Scheduler, workers, and live control plane |
| P5.3 | Health, approval, and operator projection resources | Streaming updates and production user interface |
| P5.4 | Finding create and token-checked update | Live scanner ingestion and reviewer workflow |
| P5.5 | Evidence chain records and navigation references | Evidence object store and replay renderer |
| P5.6 | Content-addressed report records | Report renderer, templates, signing, and distribution |
| P5.7 | Atomic integration event creation | Signed delivery workers and external endpoints |
| P5.8 | Tenant and context binding with injected authorization | Identity provider, SSO, administration, and retention |
| P5.9 | Remediation, resubmission evidence, retest, regression, and closure records | Developer system integrations and live retest execution |

This table describes the original service increment. The later
[offline assessment report renderer](assessment-report-rendering.md) supplies
bounded static HTML and text presentation plus explicit local file export.
Hosted presentation, signing, authorized distribution and customer acceptance
remain separate requirements; local rendering does not qualify a deployment.

## Injection requirements

Production adapters must implement three ports:

1. `AccessAuthorizer` produces a short-lived decision bound to the complete
   access check.
2. `MutationAdmitter` produces a short-lived, exact mutation admission.
3. `ServiceRepository` supplies context-scoped reads and an atomic,
   idempotent commit.

The repository contract is intentionally storage-neutral. A SQLite adapter can
serve local development, while a PostgreSQL adapter can serve concurrent or
high-availability deployment without changing service semantics.

The JSON schema validates serialized service responses. It is a wire contract
for a future HTTP, local IPC, or command adapter. Those adapters must preserve
all checks and must not treat schema validity as authorization.
