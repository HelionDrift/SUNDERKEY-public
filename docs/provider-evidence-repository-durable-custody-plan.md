# Durable repository authentication implementation plan

This is an offline software plan under the approved D013 direction. It is not
a D014 selection, repository acceptance, retention policy activation or permission
to contact a provider. The original planning baseline was MissionStore schema 38.
The [schema-39 implementation](provider-evidence-repository-durable-metadata-offline.md)
is additive authenticated-report metadata custody, not a new evidence-byte store
or a PostgreSQL shadow ledger. The layered design and verification gates below
remain the scope of that implementation.

The D013 decision record
remains unchanged. Expected repository identity, deployment dedication, account,
KMS, operational retention, legal-hold authorities, residency and activation
still require exact approved inputs and external evidence.

## Layered implementation

1. Extend [Phase 149 authentication](../src/sunderkey/provider_evidence_repository_authentication.py)
   with bounded, detached serialized-document validation and a metadata-only
   protected-effect payload. Preserve its schema 1 domain, body, IDs and hashes.
   Do not reconstruct a live principal or process-local HMAC seal from JSON.
2. Add one append-only repository-ingest authentication table and its migration
   in [MissionStore](../src/sunderkey/store.py), preserving every historical
   schema manifest from 1 through 38.
3. Add one atomic service that resolves the exact source report and dispatch
   from the same verified transaction. Require explicit expected repository
   subject/profile and current accepted authority, not caller-supplied
   dictionaries described as durable proof.
4. Reconcile every authentication row, assertion use, protected effect and source
   in both directions. Then test migrations, reopen, tampering, current-use
   denial and atomic rollback before publishing the storage implementation.

These are separate implementation and verification layers. Passing one layer
does not establish the next layer or operational custody.

## Immutable source and authority contract

The source projection must reproduce the complete available EPV lineage from
the selected EPA: report authentication ID/hash, report custody ID/hash, attempt,
acknowledgement ID/hash and provider-evidence digest. Evidence verification
cannot precede source authentication. Rehashing a nested document cannot excuse
an unrelated source value. The
[original projection](../src/sunderkey/collaboration_executor_provider_evidence.py)
defines those fields; the repository authentication producer and serialized
validator must share the same join checks.

The lifecycle, mission, scope-reference digest, complete dispatch, request,
receipt, evidence size/digest, principal operation intent and known timestamps
must agree. Metadata validation does not reverify unavailable raw evidence,
signatures, assertion issuance, current accepted scope or provider effects.

The existing `EVIDENCE_REPOSITORY_ACKNOWLEDGE` operation already binds five
intent fields: receipt-selection hash, request hash, lifecycle-policy hash,
mission ID and principal profile ID. No extra operation or implicit privilege
is required for this metadata service.

Fresh authentication and exact replay-for-use must check current repository
authority, accepted nonrevoked scope, credential/request windows, current source
rows and a clock that does not precede durable state. The service must not return
an existing row before these live checks. Historical `get`, backup, migration
and store-wide verification may validate immutable provenance at original
consumption time. A historical result cannot grant present access or be used
as live admission. Old source signatures establish historical facts, not a
renewed worker credential or permission to execute.

The positive metadata-publication API conservatively denies stopped missions
and verified local paused or recovery-pending mission health latches. Absence of
a local latch is not observed health. Historical reads remain available; a
post-stop terminal-closeout API would need its own explicit authority rules.

Keep these existing statements unchanged:

- evidence custody is `provider_report_only`;
- lifecycle policy is bound but not activated;
- provider control assertions are not independently verified;
- external ingest effects and deployment identity dedication are unverified;
- runtime and qualification effects are absent.

## Atomic metadata custody

The proposed table is `provider_evidence_repository_ingest_authentications`.
Retain canonical ERI JSON and exact projected references for the mission,
request, receipt, lifecycle, source EPA, dispatch, evidence digest/size, reported
repository/version/outcome, repository assertion and authentication timestamp.
No raw evidence, credential, private key or additional provider response is
retained by this table.

Enforce unique ERI identity/hash and repository issuer/assertion ID. Do not make
EPA, request, content digest or reported object version globally unique: the
existing contract permits distinct authenticated reports and failure outcomes.
Those reports do not establish authoritative repository-object state.

One write transaction must verify state and authority, resolve sources,
authenticate the report, consume one repository assertion, append one protected
effect, advance the principal-ledger head conditionally, insert the ERI row and
reconcile the result before commit. Use the existing
[atomic assertion recorder](../src/sunderkey/authenticated_collaboration_mission_policy.py).
No source assertion is consumed again. A late failure rolls back local metadata
custody; it must not claim an external object upload was rolled back.

Database foreign keys, insert guards and immutable/no-delete triggers supplement
the serialized and signature verifiers. An ERI row must resolve to its exact
use/effect/source; every repository-ACK use/effect must resolve to exactly one
ERI row. Checking only the forward direction would miss deleted custody with
an orphaned assertion or effect.

The [Phase 142 service](../src/sunderkey/authenticated_collaboration_executor_provider_report.py)
supplies a transaction pattern, but its early historical replay return is not
the new service's positive-use replay rule.

## Schema and compatibility review

Add the schema-39 constant, additive statements, expected manifest, recognized
initialization version and schema-check branch without editing old SQL or
manifests. Explicitly retain schema 38 in initialization's supported-version
set when the current version changes.

Migration must refuse pre-39 repository-ACK use/effect provenance that lacks
defined custody rather than backfilling unsigned JSON or ephemeral seals.
Verify the source before migration, preserve the verified backup, roll back
failed changes and do not synthesize authentication rows.

Reach reciprocal custody verification through principal-ledger verification,
mission verification, store verification and authenticated-writer snapshots.
Add internal verified row counts to both global-count paths. The public
verification-report format need not change.

Current-schema assertions need targeted review in these existing files:

- [shared downgrade fixtures](../tests/agents/test_store.py);
- [target-health gate use](../tests/agents/test_action_target_health_gate_use_phase199d.py);
- [collaboration planning](../tests/agents/test_collaboration_phase6.py);
- [plan replacement storage](../tests/agents/test_collaboration_plan_replacement_store_phase186.py);
- [executor target-health migration](../tests/agents/test_mission_store_action_executor_target_health_phase199e.py);
- [schema-38 integrity](../tests/agents/test_plan_replacement_schema38.py);
- rename compatibility;
- [store schema and reconciliation](../tests/agents/test_store_phase199_schema.py).

Update assertions about the current schema only. Keep intentional historical
38 fixtures and the 37-to-38 manifest comparison. A new empty-only downgrade
helper must run before the existing helper's early return and refuse to discard
signed repository custody or ACK provenance.

## Regression gates before storage publication

- Pure validation: genuine byte compatibility, every available source projection,
  readdressed cross-source substitutions, principal/intent/time contradictions,
  wrapper mutation and bounded native inputs before hashing or normalization.
- Migration: empty upgrade, verified backup, no fabricated rows, historical
  manifest preservation and refusal of undefined pre-39 ACK provenance.
- Database: exact source/use/effect guards, native JSON types, raw insert denial,
  foreign keys, immutable updates and deletion protection.
- Service: genuine accepted trust/scope, same-store sources, atomic commit,
  reopen, exact live replay, conflicting assertion reuse and cross-mission denial.
- Historical/live split: retained reads after expiry or revocation while new
  publication and replay-for-use remain denied by current checks.
- Reciprocal integrity: missing or substituted ERI/source/use/effect rows and
  column/JSON tampering through getters, mission/store verification and writers.
- Settlement: forced errors before and after insert restore the entire local
  logical store without inventing provider rollback or retained evidence.
- Compatibility: original critical selectors, every affected migration family,
  schema snapshots and the full suite, not only new-service tests.

Synthetic setup was independently probed on schema 38 using existing temporary
fixtures. Installing the explicit repository trust policy and accepting its
scope in the source report's store succeeds. Policy mismatch, non-increasing
installation time, premature current-use checks, expired scope and expired
assertion are denied without new custody. The fixture policy deliberately
narrows current permission to the repository principal; it does not preserve
former principals' live permission automatically. Test factories supply fixed
synthetic keys only, and their temporary directories are cleaned up.

These original schema-38 observations are preparation evidence, not proof of
schema-39 behavior, production identity provisioning or independent repository
acceptance. The schema-39 implementation has its own genuine temporary-store
regressions and the existing broader compatibility gates.
