# Offline durable repository authentication metadata

The additive MissionStore schema 39 and
`AuthenticatedProviderEvidenceRepositoryService` retain authenticated repository
receipt metadata. This is local provenance custody, not evidence-byte storage,
a repository implementation, observed cloud control enforcement or operational
acceptance. The approved D013 decision and D014 deployment questions remain
unchanged.

## Library boundary

The service takes an initialized MissionStore, the registry, an explicit expected
repository subject and profile, and a clock. `authenticate(request, receipt,
lifecycle_policy, repository_assertion=...)` selects the exact source EPA and
dispatch from that same verified database transaction. It does not accept a
caller dictionary as durable source proof or consume the source assertion again.

The source selection reproduces the complete available EPV/EPA lineage, retained
provider report and dispatch, mission and scope-reference identity, lifecycle,
request, receipt, evidence size and digest. The shared
[content validator](provider-evidence-repository-authentication-offline.md)
replays available chronology and principal intent. Current repository signature,
trust policy, accepted scope, revocation and time checks remain necessary before
positive publication. The schema-1 ERI body and its identities are unchanged.

One transaction records one repository ACK assertion use, its exact protected
effect, the conditional principal-ledger head advance and one ERI metadata row.
Late local failure rolls back that transaction. It does not undo an external
upload or establish that an object was ever uploaded.

The service has no provider port, network operation, raw evidence argument,
credential lookup, deployment step or automatic retry. A separate
[local historical inspection command](provider-evidence-repository-historical-inspection.md)
uses the shared reader without a publication identity, credential or live clock.
There is no HTTP route or new tenant-read authorization mapping.

## Historical reads and live replay

`get(authentication_id)` delegates to the shared explicit historical reader.
It verifies immutable source, signature-use and effect provenance at the original
consumption time,
including after the original permission expires or is revoked. The result is
historical metadata, not a reconstructed live principal, a renewed assertion or
an access grant. Restart does not recreate the process-local HMAC seal.

`authenticate` is positive publication or replay-for-use, even when the selected
assertion already has an exact record. Before returning a positive result it
checks the present mission state, clock, repository authority and accepted scope,
revocation, request/assertion windows and same-store sources. It must not use an
early historical return to bypass those checks.

An exact live retry returns the original durable receipt, without another row,
assertion consumption, effect or ledger advance. A later successful current
verification can produce a different ephemeral authentication timestamp; that
temporary value does not overwrite or replace the original custody. Conflicting
reuse of an assertion remains denied.

Positive use is conservatively denied for stopped missions and for verified local
mission target-health latches that are paused or recovery-pending. No local latch
means no recorded pause, not proof of healthy targets. Provider-reported worker
state is not authenticated pause evidence. Historical reads do not require an
active mission or a currently healthy latch. An eventual post-stop closeout path
must be explicit, with its own fresh authority and lineage rules.

This API authenticates a metadata report. It is not action admission, dispatch,
target-health collection or execution authority.

## Storage and reconciliation

The append-only table is
`provider_evidence_repository_ingest_authentications`. It stores canonical ERI
JSON and projected identities for the mission, request, receipt, lifecycle,
source EPA and report, attempt, acknowledgement, dispatch, evidence digest/size,
reported repository object/version, outcome, repository principal and assertion,
authentication time and unchanged boundary statuses.

ERI identity/hash and repository issuer/assertion identity are unique. Source
EPA, request, digest and reported object version are not globally unique: the
existing contract permits distinct reports and failed outcomes. Reported object
metadata is not an authoritative object-state ledger.

Foreign keys, native JSON/type and source/use/effect insert guards supplement
the full integrity verifier. Updates and deletes are rejected. Schema and
application verification are complementary: SQL shape checks do not replace
content hashes or signature verification.

Every ERI must reconcile to its exact source documents, repository assertion use
and sole protected effect. Conversely, every repository ACK use and effect must
have exactly one ERI. Orphan, missing, substituted or cross-mission provenance
is invalid. Historical retrieval, mission/store verification and authenticated
writer verification reach the same reciprocal checks. Store-wide row counts
include this custody rather than overlooking rows outside a mission iteration.

The retained ERI has the shared bounded-native validation limits. A row's JSON
is checked before nested contract replay, and its canonical form and projected
columns must agree. No serialized JSON alone becomes signature or current
permission evidence.

## Migration and regression scope

Schema 39 is appended to the frozen schemas 1 through 38. An upgrade retains a
verified backup and does not fabricate an ERI, activate a lifecycle or backfill
an ephemeral seal. Pre-39 repository ACK use or effect provenance without defined
custody is refused instead of silently assigned a new authentication row.

The [implementation plan](provider-evidence-repository-durable-custody-plan.md)
identifies the affected current-schema consumers and historical fixtures.
Current-version assertions advance to 39; intentional 37-to-38 manifest
comparisons remain historical. The shared legacy-fixture helper can remove only
empty schema-39 custody and refuses signed repository history before an early
return or any destructive fixture adjustment.

Regression gates cover genuine temporary trust/scope setup, same-store source
selection, one-use atomic commit and rollback, reopen, exact current retry,
expiry/revocation and stop/pause denial, historical readability, reciprocal and
projected-column tampering, raw SQL guards, migration/backup and preserved old
manifests. Existing action, target-health and plan-replacement regressions remain
required in addition to the new tests.

## Claims that do not change

- Evidence custody remains `provider_report_only`.
- Lifecycle is `prepared_policy_bound_not_activated`.
- Repository controls remain `provider_assertions_not_independently_verified`.
- External effects remain `authenticated_report_unverified_effect`.
- Deployment identity dedication remains unverified.
- Runtime, authority and qualification effects are not promoted.

The new durable fact is authentication-report metadata with assertion and ledger
provenance. Retention, residency, encryption, quarantine, immutability, cloud IAM,
object existence and production repository acceptance still require independent
external evidence. Tests use synthetic keys and isolated temporary stores,
not real credentials or deployed infrastructure.
