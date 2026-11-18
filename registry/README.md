# Expert Registry

The expert registry is the authoritative, versioned catalog used by the
SUNDERKEY expert control plane. It describes roles, reporting hierarchy,
policy templates, operating boundaries, and the count contract for the
Army of Experts.

## Files

- `army-v1.json` is the active version 1 catalog.
- `army-v2.json` is the additive D015 target catalog with all 451 profiles. It
  preserves every v1 profile record and defines all 48 additions as inactive.
- `schemas/registry-v2.schema.json` closes the v2 catalog identity, version,
  structure, and exact count contract.
- `attack-vectors-v2.json` binds all 391 v2 specialists to stable coverage
  anchors, supporting specialists, independent validators, evidence,
  restoration, qualification, blind-spot, and versioned standards context.
- `schemas/attack-vector-catalog-v2.schema.json` defines the closed vector
  catalog structure and exact coverage summary.
- `capabilities-army-v2.json` preserves all 348 v1 capability definitions,
  adds 43 v2 definitions, and binds all 391 primary owners to 782
  vector-derived supporting edges without creating a routing policy.
- `schemas/capability-catalog-v2.schema.json` closes the v2 graph identity,
  versions, counts, and nonempty supporting-edge structure.
- `qualification-standard-v2.json` binds the existing independent-review
  policy and all qualification gates to the exact Army v2 registry and
  capability graph.
- `qualification-plans-army-v2.json` gives all 391 specialists exact vector,
  capability, validator, evidence, restoration, scenario, and critical-failure
  bindings without changing qualification state.
- `schemas/qualification-standard-v2.schema.json` and
  `schemas/qualification-plan-catalog-v2.schema.json` close the v2 standard
  and 391-plan count and structure contracts.
- `candidate-blueprints-army-v2.json` gives all 391 specialists exact
  provider-neutral adapter, input, output, control, evidence, restoration,
  component, and six-stage test contracts while leaving candidates
  unimplemented.
- `schemas/candidate-blueprint-catalog-v2.schema.json` closes the blueprint
  identity, input bindings, 391-profile count, component set, and test matrix.
- `implementation-work-packages-v2.json` binds every v2 specialist blueprint
  to a commander-owned eight-stage build and validation DAG.
- `specialist-implementation-roadmap-v2.json` schedules all 391 packages into
  30 risk-prioritized, command-deconflicted, validator-capacity-bound waves and
  25 commander queues without assigning or dispatching work.
- `schemas/implementation-work-package-catalog-v2.schema.json` and
  `schemas/specialist-implementation-roadmap-v2.schema.json` define the closed
  package and scheduling structures.
- `candidate-implementation-strategy-v1.json` records the repository owner's
  exact D016 implementation-substrate approval without granting qualification,
  routing, deployment, credentials, or target authority.
- `offline-specialist-components-v1.json` binds 37 partial inert algorithms
  across 34 existing specialist profiles to current source bytes and existing
  package, commander and validator ownership. It also binds the unsigned
  common-task composer without creating a new specialist or granting routing,
  independent acceptance, qualification or positive-use authority.
- `candidate-adapters-reference-v1.json` binds six cross-domain reference
  adapters to their exact Phase 155 blueprints, source digest, isolation class,
  deny-all resource policy, typed contracts, and evidence semantics.
- `schemas/candidate-adapter-catalog-v1.schema.json` defines the closed Phase
  157 reference adapter catalog format.
- `candidate-adapter-development-gates-v1.json` records all 36 Phase 157
  reference-slice development gates. Thirty reference gates pass and all six
  containment gates remain blocked pending a real backend conformance receipt.
- `candidate-containment-conformance-suites-v1.json` defines the exact rootless
  Podman and jailed Firecracker probe sets required before a backend can receive
  a synthetic-only Phase 157 admission. The catalog is not evidence that either
  backend is installed or conformant.
- `army-expansion-roadmap-v1.json` is the content-addressed, approved plan
  for the parallel Army v2 migration to 391 specialists, 25 domain commanders,
  and 35 shared profiles. It has no qualification, routing, execution,
  deployment, or production-authority effect.
- `schemas/army-expansion-roadmap-v1.schema.json` defines the closed D015
  roadmap, exact count contract, additions, standards inputs, and ordered
  delivery phases.
- `capability-roadmap-v1.json` is the active content-addressed program roadmap
  with 83 dependency-ordered packages and nine evidence gates.
- `schemas/capability-roadmap-v1.schema.json` documents the closed roadmap
  structure and release-state vocabulary.
- `external-capability-study-v1.json` records 26 dated primary vendor sources,
  18 conservative capability gaps, seven proposed role additions, and 16
  proposal-only V9 roadmap packages without granting qualification, parity,
  superiority, deployment, target authority, or operational effect.
- `schemas/external-capability-study-v1.schema.json` closes the study identity,
  source bindings, counts, claim boundaries, role-proposal state, and roadmap
  package structure.
- `v9-offline-adoption-v1.json` projects all seven study roles and 16 V9
  packages into an owner-approved, source-bound offline backlog. Its exact
  projection verifier rejects source drift and extra fields. It creates no
  routing, package execution, live target authority, or qualification.
- `schemas/asset-lifecycle-review-v1.schema.json` closes the nonqualifying
  V9.2 disappearance-review record. No candidate applies an asset tombstone.
- `schemas/event-history-checkpoint-v1.schema.json` closes the optional V9.3
  exact-head signature record. External key custody and anchoring are absent.
- `schemas/human-review-statement-v1.schema.json` closes one signed V9.14
  historical opinion. It does not authenticate a reviewer or admit approval.
- `schemas/mcp-local-reference-closure-v1.schema.json` closes a bounded V9.15
  local JSON Pointer target check without external fetch or tool execution.
- `schemas/emerging-threat-review-v1.schema.json` describes a metadata-only
  V9.4 advisory-to-asset review without exploit content or target interaction.
- `schemas/emerging-threat-review-statement-v1.schema.json` describes an
  externally signed, historical V9.4 opinion without reviewer-role authority.
- `schemas/deception-lifecycle-review-v1.schema.json` describes a metadata-only
  V9.8 tripwire lifecycle with declared placement and cleanup receipts.
- `schemas/synthetic-blast-radius-review-v1.schema.json` describes a bounded,
  nonqualifying V9.7 synthetic impact-path review with unverified closure.
- `schemas/ai-validation-plan-v1.schema.json` describes a non-executable V9.12
  target profile and bounded adversarial case plan.
- `schemas/cross-service-chain-review-v1.schema.json` describes the
  nonqualifying C4.9 per-hop admission, evidence, and cleanup review.
- `schemas/api-session-sequence-review-v1.schema.json` describes bounded,
  nonqualifying V9.5 caller-declared session ordering over sanitized API events.
- `schemas/control-health-window-review-v1.schema.json` describes bounded,
  nonqualifying V9.10 control-health declarations over exact action windows.
- `asset-reconciliation-policy-v1.json` defines the closed Phase 208 passive
  source, identity-linking, confidence, freshness, and no-authority policy.
- `schemas/asset-reconciliation-policy-v1.schema.json` and
  `schemas/asset-reconciliation-snapshot-v1.schema.json` close the policy and
  content-addressed reconciliation output formats.
- `schemas/target-authentication-adapter-contract-v2.schema.json` closes the
  seven provider-binding, credential-provenance, policy, command, flow-evidence,
  result, and receipt record kinds plus their fixture and external-observation
  conditions. It provides no credential resolver, provider adapter, target
  interaction, authority, qualification, or deployment evidence.
- `schemas/orchestration-journal-v1.schema.json` closes the Phase 197 durable
  job, message, action-execution handoff, attempt, quarantine, terminal
  observation, authenticated reconciliation, projection, and event records.
  It provides no production listener, worker, signer, credential access,
  target interaction, or authoritative execution result.
- `schemas/target-health-custody-v1.schema.json` closes the Phase 198A trust
  root, collector policy, exact-policy revocation, signed custody envelope,
  signing context, verification result, custody receipt, and custody event
  records plus the Phase 199 current-head binding and atomic inspection
  records. It provides no collector, private key, network or target access,
  MissionStore mutation, pause or resume decision, control effect, or
  production authority.
- `schemas/target-health-gate-v1.schema.json` closes the Phase 199B subject,
  observation, transition, durable head, recovery-intent, independent Control
  resumption, and decision records. MissionStore schema version 35 supplies the
  durable four-table latch foundation. Phase 199C adds the transaction-scoped
  MissionStore service and historical verifier over those records. Phase 199D
  adds schema version 36 action health use custody and integrates fresh gate
  decisions into Phase 195 positive publication and admission paths. These
  boundaries do not collect health, integrate Phase 196 execution, enforce an
  executor pause, or perform a network or target action.
- `capabilities-pilot-v1.json` maps all 20 pilot specialists to explicit
  routing capabilities.
- `routing-policy-pilot-v1.json` is the trusted pilot routing policy.
- `capabilities-army-v1.json` maps all 348 specialists to explicit routing
  capabilities.
- `routing-policy-army-qualified-v1.json` is the qualified-only full-Army
  routing policy.
- `qualification-standard-v1.json` defines the common specialist
  qualification gates and independent review policy.
- `qualification-plans-army-v1.json` binds every specialist to an explicit
  evaluation objective, primary capabilities, scenario family, and gates.
- `qualification-authority-dossier-d008.json` records the D008 alternatives
  and the previously pending recommendation.
- `qualification-authority-decision-d008.json` records explicit approval of
  the complete recommended D008 option bundle.
- `candidate-enrollment-dossier-d009.json` records the D009 requirements,
  alternatives, recommendation, and explicit choices.
- `candidate-enrollment-decision-submission-d009.json` records the explicit
  repository-owner approval inputs for the full recommended D009 bundle.
- `candidate-enrollment-decision-d009.json` is the deterministic approved
  D009 architecture record and authorizes enrollment contract implementation.
- `candidate-enrollment-implementation-d009.json` records deterministic
  completion of all seven authorized contract steps without live enrollment.
- `candidate-enrollment-activation-dossier-d011.json` records the eight D011
  checkpoint custody and activation choices before owner selection.
- `candidate-enrollment-activation-decision-submission-d011.json` records the
  explicit repository-owner approval inputs for the recommended D011 bundle.
- `candidate-enrollment-activation-decision-d011.json` is the deterministic
  D011 decision record that authorizes checkpoint and release contract work.
- `candidate-enrollment-release-policy-d011.json` is the deterministic D011
  checkpoint, release ordering, authority, recovery, and retention policy.
- `candidate-enrollment-canary-preparation-d011.json` is the deterministic
  single-candidate external-input and activation-gate packet.
- `candidate-enrollment-activation-implementation-d011.json` records
  deterministic completion of all six D011 contract and offline-component
  steps while keeping production activation blocked.
- `candidate-enrollment-production-custody-dossier-d012.json` records the
  unselected production platform, adapter, ledger, repository, identity, and
  resilience alternatives and recommended bundle.
- `candidate-enrollment-production-custody-decision-submission-d012.json`
  records the explicit repository-owner approval inputs for the recommended
  D012 production custody bundle.
- `candidate-enrollment-production-custody-decision-d012.json` is the
  deterministic D012 decision record that authorizes production custody
  contract implementation without selecting infrastructure.
- `schemas/candidate-enrollment-production-custody-contract-v1.schema.json`
  closes the provider-neutral D012 interface contract and exact decision,
  architecture, owner-input, separation, and no-effect boundaries.
- `schemas/candidate-enrollment-production-custody-conformance-suite-v1.schema.json`
  closes the twelve-case executable provider conformance suite.
- `schemas/candidate-enrollment-production-custody-conformance-report-v1.schema.json`
  closes ordered case observations, outcomes, variant-specific evidence
  profiles, and the `reference_simulation_nonqualifying` and
  `unattested_external_claim` no-effect report boundaries.
- `provider-evidence-custody-dossier-d013.json` records twelve unselected
  evidence repository, encryption, access, lifecycle, hostile-content,
  residency, and rollout choices with a complete recommended bundle.
- `provider-evidence-custody-decision-submission-d013.json` records explicit
  repository-owner approval inputs for all twelve recommended D013 options.
- `provider-evidence-custody-decision-d013.json` is the deterministic D013
  decision record authorizing evidence-custody contract implementation without
  selecting infrastructure or authorizing evidence retention.
- `production-deployment-decision-dossier-d014.json` is the deterministic,
  content-addressed Phase 187 owner packet for the still-unselected production
  deployment decision. It preserves three exact options for each of 19 D014
  questions, binds five approved or current source artifacts plus 16 exact
  repository schema digests, and catalogs two unselected Phase 186D owner
  questions without granting authority.
- `schemas/production-deployment-decision-dossier-v1.schema.json` closes the
  D014 dossier identity, exact sources, decision questions, related pending
  decision boundaries, limitations, and no-effect contract.
- `schemas/provider-evidence-repository-ingest-request-v1.schema.json` and
  `schemas/provider-evidence-repository-ingest-receipt-v1.schema.json` define
  the provider-neutral conditional quarantine ingest boundary and its
  explicitly unauthenticated provider result.
- `schemas/provider-evidence-lifecycle-policy-v1.schema.json` defines the
  mission-bound retention, legal-hold, deletion, encryption, access, residency,
  classification, and hostile-content policy contract.
- `schemas/provider-evidence-repository-ingest-authentication-v1.schema.json`
  defines exact repository receipt authentication, source report and dispatch
  lineage, lifecycle reconciliation, and the unverified repository-control
  boundary.
- `collaboration-authority-dossier-d001-d005.json` records the combined
  pending collaboration authority alternatives and recommended option bundle.
- `collaboration-authority-decision-submission-d001-d005.json` records the
  explicit repository-owner approval inputs for the recommended D001 through
  D005 collaboration authority bundle.
- `collaboration-authority-decision-d001-d005.json` is the deterministic
  decision record that authorizes reconfiguration contract implementation
  without changing live mission authority.
- `collaboration-reconfiguration-policy-d001-d005.json` is the deterministic,
  inactive authority policy for all five approved transition families.
- `schemas/managed-api-evaluation-boundary.schema.json` documents the
  approved D010 managed API architecture and closed runtime binding.
- `candidate-implementations-v1.json` catalogs content-addressed specialist
  candidate definitions without selecting a provider or enabling execution.
- `candidate-blueprints-army-v1.json` defines the exact provider-neutral
  implementation blueprint for every specialist.
- `candidate-components-v1.json` contains the five disabled component
  artifacts for the Passive OSINT contract fixture.
- `schemas/registry.schema.json` documents the registry structure.
- `schemas/mission.schema.json` documents mission request inputs.
- `schemas/event.schema.json` documents typed mission events.
- `schemas/capability-catalog.schema.json` documents capability mappings.
- `schemas/routing-policy.schema.json` documents trusted routing policy.
- `schemas/routing-request.schema.json` documents structured routing input.
- `schemas/collaboration-plan.schema.json` documents the output-only
  CollaborationPlan version 1 contract.
- `schemas/collaboration-plan-replacement-preflight-v1.schema.json` documents
  the inactive, content-addressed replacement selection that binds exact plans,
  the committed mission policy, durable source snapshots, item dispositions,
  work mapping, completed-result preservation, cross-command evidence, and the
  authorities required by a future authenticated atomic commit.
- `collaboration-plan-replacement-authority-plan-v1.json` binds all 16 Phase
  184 replacement authority requirements to exact operations, roles, work
  items, time windows, authentication contracts, and replay policy.
- `schemas/collaboration-plan-replacement-authority-plan-v1.schema.json`
  closes the Phase 186A authority-plan structure and preserves its inactive,
  source-verification-required boundary.
- `schemas/collaboration-plan-replacement-authority-upgrade-v2.schema.json`
  closes the Phase 186B1 principal-identity upgrade, including exact profile
  self-binding and registered commander bindings for command authorities.
- `schemas/collaboration-plan-replacement-commit-receipt-v1.schema.json`
  closes the Phase 186B2 atomic replacement receipt over the active-head
  transition, source snapshots, authority custody, settlements, carry-forwards,
  and replacement work initialization.
- `schemas/collaboration-execution-channel-policy-v1.schema.json` documents
  the signed-selection candidate for the D005 execution channel.
- `schemas/collaboration-execution-channel-authentication-v1.schema.json`
  documents dual-principal authentication of one exact channel selection.
- `schemas/collaboration-execution-channel-policy-commit-receipt-v1.schema.json`
  documents durable policy custody and both consumed approval assertions.
- `schemas/collaboration-fenced-worker-session-v1.schema.json` documents an
  inactive worker session bound to exact ownership, credential, and
  predecessor-revocation fences.
- `schemas/collaboration-execution-transfer-request-v1.schema.json` documents
  an inactive handoff or cancellation request bound to exact control and
  worker-session state.
- `schemas/collaboration-execution-acknowledgement-v1.schema.json` documents
  an external worker acknowledgement and any required credential-revocation
  proof.
- `schemas/collaboration-execution-transfer-request-authentication-v1.schema.json`
  documents signed control-plane authorization of one exact transfer request.
- `schemas/collaboration-execution-acknowledgement-authentication-v1.schema.json`
  documents signed external worker acknowledgement authentication.
- `schemas/collaboration-execution-timeout-resolution-v1.schema.json` documents
  fail-closed handling of an incomplete authenticated acknowledgement set.
- `schemas/collaboration-execution-timeout-authentication-v1.schema.json`
  documents independent Control authentication of one exact timeout decision.
- `schemas/collaboration-execution-transfer-completion-v1.schema.json`
  documents successful completion from the exact authenticated acknowledgement
  set while keeping target activation behind an atomic durable commit.
- `schemas/collaboration-execution-terminal-custody-plan-v1.schema.json`
  documents the mutually exclusive terminal outcome and ordered principal
  assertion custody required by a later atomic store transaction.
- `schemas/collaboration-execution-session-authority-v1.schema.json`
  documents short-lived fenced authority derived from an activated plan or
  completed terminal custody.
- `schemas/collaboration-execution-session-revocation-v1.schema.json`
  documents a pending explicit revocation bound to exact authority, session,
  credential, reason, and decision-owner assertion.
- `schemas/collaboration-execution-session-activation-request-v1.schema.json`
  documents a non-executing dual-principal request for one exact fenced
  session authority.
- `schemas/collaboration-execution-session-activation-authentication-v1.schema.json`
  documents authenticated control-plane authorization and exact worker
  acceptance of one activation request.
- `schemas/collaboration-execution-session-revocation-authentication-v1.schema.json`
  documents independent Control authentication of one explicit session
  revocation.
- `schemas/collaboration-execution-session-activation-commit-receipt-v1.schema.json`
  documents atomic authority and dual-principal activation custody with no
  external runtime effect.
- `schemas/collaboration-execution-session-revocation-commit-receipt-v1.schema.json`
  documents atomic independent-Control revocation custody with no external
  runtime effect.
- `schemas/collaboration-execution-session-authority-status-v1.schema.json`
  documents a content-addressed, read-only projection of pending, available,
  revoked, and expired control-plane authority.
- `schemas/collaboration-executor-dispatch-v1.schema.json` documents one exact
  provider-neutral operation dispatch bound to available authority, mission,
  worker, session, credential, fence, policy, input, sequence, and time.
- `schemas/collaboration-executor-acknowledgement-v1.schema.json` documents an
  unverified provider report for one exact dispatch and fenced worker session.
- `schemas/collaboration-executor-acknowledgement-authentication-v1.schema.json`
  documents exact worker-principal authentication of a provider report while
  retaining the unverified external-effect boundary.
- `schemas/collaboration-executor-dispatch-authentication-v1.schema.json`
  documents non-worker control-plane authentication of exact ordinary and
  safety-reducing dispatch selections.
- `schemas/collaboration-executor-dispatch-reservation-receipt-v1.schema.json`
  documents atomic pre-invocation custody of an authenticated dispatch and its
  authorizer assertion without claiming adapter or target effects.
- `schemas/collaboration-executor-delivery-claim-v1.schema.json` documents a
  bounded, content-addressed claim and expired-lease takeover contract without
  claiming deployment identity, adapter invocation, or target effects.
- `schemas/collaboration-executor-delivery-claim-commit-receipt-v1.schema.json`
  documents atomic durable claim custody while retaining the not-started
  external-effect boundary.
- `schemas/collaboration-executor-invocation-preparation-v1.schema.json`
  documents exact operation-byte revalidation and durable-before-call adapter
  attempt material without claiming invocation.
- `schemas/collaboration-executor-invocation-preparation-commit-receipt-v1.schema.json`
  documents atomic durable custody for an invocation preparation.
- `schemas/collaboration-executor-invocation-resolution-v1.schema.json`
  distinguishes failure before invocation, provider report receipt, and
  uncertain external outcomes with reconstructable retry rules.
- `schemas/collaboration-executor-invocation-resolution-commit-receipt-v1.schema.json`
  documents atomic durable custody for one terminal local resolution.
- `schemas/collaboration-executor-invocation-recovery-assessment-v1.schema.json`
  documents read-only, non-authorizing recovery classification for durable
  invocation attempts.
- `schemas/collaboration-executor-provider-report-v1.schema.json` documents
  complete untrusted provider-report material bound to one prepared invocation
  without claiming authentication.
- `schemas/collaboration-executor-provider-report-commit-receipt-v1.schema.json`
  documents atomic custody of a complete report and matching terminal local
  resolution.
- `schemas/collaboration-executor-provider-report-authentication-v1.schema.json`
  documents exact worker-principal authentication bound to retained provider
  report custody without treating its evidence digest as verified.
- `schemas/collaboration-executor-provider-report-authentication-receipt-v1.schema.json`
  documents atomic custody of that authentication and its worker assertion
  ledger provenance.
- `schemas/collaboration-executor-provider-evidence-verification-v1.schema.json`
  documents exact evidence-byte digest verification while leaving media type,
  semantic meaning, and the reported external effect unverified.
- `schemas/collaboration-executor-provider-evidence-verification-receipt-v1.schema.json`
  documents read-only verification against durable report authentication and
  makes transient, non-retained evidence custody explicit.
- `schemas/qualification-standard.schema.json` documents the qualification
  standard.
- `schemas/qualification-plan-catalog.schema.json` documents profile-specific
  qualification plans.
- `schemas/qualification-evaluation-suite.schema.json` documents synthetic
  evaluation suite inputs.
- `schemas/qualification-observation-set.schema.json` documents unsigned
  local observation inputs.
- `schemas/candidate-implementation-catalog.schema.json` documents
  provider-neutral candidate implementation bindings.
- `schemas/candidate-blueprint-catalog.schema.json` documents specialist
  candidate blueprint contracts.
- `schemas/candidate-component-catalog.schema.json` documents strict
  provider-neutral component artifacts.
- `schemas/candidate-evaluation-submission.schema.json` documents the closed
  unsigned synthetic evaluation submission.
- `schemas/qualification-authority-dossier.schema.json` documents the D008
  decision dossier.
- `schemas/qualification-authority-decision.schema.json` documents the
  approved D008 decision record.
- `schemas/candidate-enrollment-dossier.schema.json` documents the D009
  candidate-owner and evidence-repository enrollment decision dossier.
- `schemas/candidate-enrollment-decision-record.schema.json` documents an
  explicit owner-selected D009 architecture bundle without applying trust.
- `schemas/candidate-enrollment-activation-dossier-v1.schema.json` documents
  the D011 checkpoint custody and activation decision dossier.
- `schemas/candidate-enrollment-activation-decision-record-v1.schema.json`
  documents an explicit owner-selected D011 bundle without applying it.
- `schemas/candidate-enrollment-release-policy-v1.schema.json` documents the
  approved D011 checkpoint and release implementation policy.
- `schemas/candidate-enrollment-checkpoint-record-v1.schema.json` documents
  content-addressed, versioned local checkpoint mirror records.
- `schemas/candidate-enrollment-checkpoint-commit-receipt-v1.schema.json`
  documents atomic commit and exact idempotent retry outcomes.
- `schemas/candidate-enrollment-release-ledger-entry-v1.schema.json` documents
  hash-chained append-only release events and authority bindings.
- `schemas/candidate-enrollment-catalog-promotion-receipt-v1.schema.json`
  documents a content-addressed catalog repository promotion result.
- `schemas/candidate-enrollment-release-completion-receipt-v1.schema.json`
  documents terminal ordered release completion and its still-closed live gate.
- `schemas/candidate-enrollment-release-recovery-assessment-v1.schema.json`
  documents read-only partial-state classification and recovery eligibility.
- `schemas/candidate-enrollment-release-recovery-receipt-v1.schema.json`
  documents dual-control same-digest recovery completion.
- `schemas/candidate-enrollment-canary-preparation-v1.schema.json` documents
  the still-inactive single-candidate canary input and gate packet.
- `schemas/candidate-enrollment-activation-implementation-report-v1.schema.json`
  documents qualification-neutral D011 implementation completion evidence.
- `schemas/candidate-enrollment-production-custody-dossier-v1.schema.json`
  documents the pending D012 production custody decision boundary.
- `schemas/candidate-enrollment-production-custody-decision-record-v1.schema.json`
  documents an explicit owner-selected D012 bundle without applying it.
- `schemas/candidate-enrollment-signer-authorization.schema.json` documents
  offline-root authorization for separated enrollment catalog signers.
- `schemas/candidate-enrollment-catalog.schema.json` documents reviewed,
  versioned enrollments, renewal, rotation, revocation, and logical repository
  bindings.
- `schemas/candidate-enrollment-implementation-report.schema.json` documents
  qualification-neutral D009 contract completion evidence.
- `schemas/collaboration-authority-dossier.schema.json` documents the
  combined D001 through D005 collaboration authority decision dossier.
- `schemas/collaboration-authority-decision-record-v1.schema.json` documents
  an explicit owner-selected D001 through D005 bundle without applying it.
- `schemas/collaboration-reconfiguration-authority-policy-v1.schema.json`
  documents the inactive authority, parameter, and transition policy contract.
- `schemas/collaboration-ownership-chain-entry-v1.schema.json` documents each
  immutable, bounded D002 ownership transition and its exact predecessor.
- `schemas/collaboration-ownership-revocation-v1.schema.json` documents an
  independent Control request bound to the exact current ownership-chain head.
- `schemas/collaboration-ownership-transition-preflight-v1.schema.json`
  documents the verified policy, work-fence, candidate, and projected-chain
  bindings for a read-only delegation or planned-owner return result.
- `schemas/collaboration-ownership-revocation-preflight-v1.schema.json`
  documents exact-head, inactive-fence, planned-owner, policy, and projected
  entry bindings for a read-only independent Control revocation result.
- `schemas/collaboration-ownership-privileged-reassignment-preflight-v1.schema.json`
  documents the D001 role, authority shape, inactive fence, replacement
  qualification, and projected chain bindings for a read-only result.
- `schemas/collaboration-ownership-privileged-reassignment-authentication-v1.schema.json`
  documents exact three-party authentication and the conditional fourth
  authority required when the independent Control role is replaced.
- `schemas/collaboration-ownership-revocation-authentication-v1.schema.json`
  documents planned-owner acceptance and independent Control approval of one
  exact revocation preflight without current-owner consent.
- `schemas/collaboration-ownership-authentication-v1.schema.json` documents
  current-owner authorization, proposed-owner acceptance, and independent
  Control approval of one exact ownership-transition preflight.
- `schemas/collaboration-ownership-commit-receipt-v1.schema.json` documents
  the atomic durable chain commit, effective-owner projection, and all three
  principal-ledger results.
- `schemas/collaboration-ownership-revocation-commit-receipt-v1.schema.json`
  documents the atomic Control revocation commit, restored planned-owner
  projection, and both principal-ledger results.
- `schemas/collaboration-mission-reconfiguration-policy-v1.schema.json`
- `schemas/collaboration-mission-policy-authentication-v1.schema.json`
- `schemas/collaboration-mission-policy-commit-receipt-v1.schema.json`
  documents mission-scoped parameter selections, transition flags, approval
  references, and monotonic policy replacement without runtime activation.
- `schemas/qualification-trust-policy.schema.json` documents the signed
  qualification trust-policy contract.
- `schemas/qualification-reviewer-credential.schema.json` documents the
  role-scoped short-lived reviewer credential contract.
- `schemas/qualification-evidence-manifest.schema.json` documents the signed
  content-addressed qualification evidence contract.
- `schemas/qualification-reviewer-attestation.schema.json` documents the
  reviewer-signed evidence conclusion contract.
- `schemas/qualification-decision.schema.json` documents the authority-signed
  initial qualification approval contract.

The schemas use JSON Schema draft 2020-12. They are suitable for editor
support and structural validation. The Python runtime validators remain
authoritative for cross-record checks that JSON Schema cannot express
cleanly, including hierarchy membership, referenced profile existence,
profile kind relationships, exact count reconciliation, mission policy,
event ordering, collaboration-graph dependencies, and separation of duties.

## Catalog contract

The active catalog has this fixed composition:

| Item | Count |
| --- | ---: |
| Maneuver groups | 5 |
| Domain commands | 23 |
| Specialists | 348 |
| Domain commanders | 23 |
| Shared profiles | 32 |
| Total profiles | 403 |
| Pilot specialists | 20 |

The 403 profile total is the sum of 348 specialists, 23 domain
commanders, and 32 shared profiles. Maneuver groups and domain commands
are hierarchy records, not additional profiles.

## Stable identifiers

Identifiers encode role placement:

- Maneuver groups: `GA` through `GE`
- Domain commands: `AOE-GA-D01`
- Specialists: `AOE-GA-D01-S01`
- Domain commanders: `AOE-GA-D01-CMD`
- Shared profiles: `AOE-HQ-01`

An identifier is a stable reference. Rename the display name when needed,
but do not reuse an existing identifier for a different responsibility.
Retire a superseded profile by changing its status to `retired`, then add
a new profile with a new identifier.

## Profiles and policies

Every profile declares:

- its kind, version, lifecycle status, and mission;
- its policy template;
- its maximum autonomous action tier;
- its minimum evidence level;
- hierarchy references and searchable tags;
- whether it belongs to the initial pilot set.

Policy templates separate what a role may do, what it may not do, and the
conditions that require it to stop. A profile policy does not create legal
authority, enlarge mission scope, or replace a mission-specific
authorization.

The `pilot` flag marks an initial qualification and evaluation cohort. It
does not bypass normal mission assembly or activate a profile
automatically.

## Capability routing

Capability routing uses a versioned sidecar instead of inferring expertise
from profile names, mission prose, or search tags. Every capability catalog
must match the expert catalog ID and version exactly.

Each pilot specialist has one or more primary capability IDs and may have
supporting capability IDs. Primary owners rank before supporting owners.
Only the trusted routing policy can permit a supporting fallback.

The pilot policy is limited to qualified pilot profiles in offline,
synthetic, or test environments. It cannot route a production mission or
an action tier above the declared profile autonomy.

Capability catalog schema v2 adds an explicit `all_specialists` scope. The
full-Army catalog gives every specialist exactly one primary capability and
preserves the pilot mappings and supporting links. Its bundled policy allows
only qualified profiles, so the 328 specialists in `defined` status remain
visible but ineligible. The `army-readiness` command reports that distinction
at Army, group, command, and profile levels.

Catalog and policy files are trusted deployment configuration. The loader
validates their structure and cross-record invariants but does not establish
who selected or modified a file. Deployments must protect reviewed files and
compare the canonical SHA-256 digests emitted in a routing decision with
approved values.

Capability mappings do not grant authority. They only produce explicit
specialist IDs for a normal `MissionRequest`, which remains subject to
mission validation and Joint Mission Cell assembly.

## Qualification planning

Phase 21 separates qualification planning from evidence and status. The
qualification standard is bound to the exact registry and full-Army
capability digest. It requires offline, synthetic, or test evaluation, at
least two evaluators, independent Control and Assurance review, no
self-attestation, independent review for every gate, and zero permitted
critical failures.

The plan catalog covers all 348 specialists exactly once. Each plan binds the
profile's stable identity, narrow technical focus, primary capabilities,
unique scenario family, evaluation objective, and all eight common gates.
The runtime rejects incomplete coverage or a binding mismatch.

The standard produces 29 minimum scenarios and 26 minimum passing scenarios
per specialist. Across the current Army, this is 2,784 gate assessments and
10,092 minimum scenarios. These are planned evaluations, not evidence or
completed work.

`qualification-coverage` projects the backlog by Army, group, command, gate,
and profile. It does not accept evidence, make a qualification decision, or
change registry status. The authority and signed evidence contract for a
future decision remains pending.

## Advisory qualification evaluation

Phase 22 adds strict runtime and JSON Schema contracts for synthetic
evaluation suites and unsigned local observations. A suite is bound to the
exact registry, full-Army capability catalog, qualification standard, plan
catalog, profile, scenario family, and candidate artifact digest. It must
cover every gate with allowed environments, unique cases, contiguous
ordinals, and at least the standard's required number of scenarios.

An observation set must bind the exact suite, profile, candidate, and every
case exactly once. The evaluator scores the standard's numerical pass and
critical-failure thresholds and emits a deterministic report. It never
changes registry status or routing eligibility.

The checked-in Passive OSINT fixture has 29 synthetic cases and 29 unsigned
passing observations. It demonstrates contract validation only. It is not
evidence that a real candidate is qualified. Independent evaluator, Control,
and Assurance review remain `not_performed`. D008 remained pending at this
advisory evaluation phase and was subsequently decided in Phase 31.

## Candidate implementation inventory

Phase 23 separates specialist role definitions from concrete candidate
implementations. Each candidate binds one planned specialist to an exact
lifecycle, implementation kind, five component digests, and one
domain-separated artifact root.

The component digests cover the behavior contract, instruction bundle,
knowledge manifest, runtime manifest, and tool policy. They are content
identities, not deployment, provenance, safety, or competence claims.

The checked-in catalog contains only `fixture.passive-osint`, explicitly
labeled `contract_fixture`. It binds the Phase 22 contract fixture but does
not count as a nonfixture implementation. The inventory therefore reports
zero profiles with nonfixture candidates and 348 specialist implementation
gaps.

The catalog is intentionally provider-neutral. It contains no secret,
credential, endpoint, model selector, target, tool connection, or executable
payload. Candidate lifecycle does not change registry qualification status or
routing eligibility.

## Specialist candidate blueprints

Phase 24 gives every one of the 348 specialists an exact, deterministic
implementation blueprint. Each blueprint binds the specialist identity and
mission to its policy template, action and evidence boundaries, capabilities,
qualification scenario, required gates, command mission, collaboration role,
and operational boundary.

Every blueprint requires exactly five implementation components: a behavior
contract, instruction bundle, knowledge manifest, runtime manifest, and tool
policy. This creates 1,740 explicit component requirements across the Army.
The runtime reconstructs each blueprint from the authoritative registry,
capability catalog, qualification plans, and standard, so a rehashed content
substitution is rejected.

Candidate definitions now bind the exact blueprint digest in addition to
their five component digests. Blueprints remain specifications only. They do
not choose a provider or model, create tools, grant authority, execute work,
or change qualification and routing status.

## Candidate component onboarding

Phase 25 defines strict artifact contracts for the five blueprint component
types. Every component binds one candidate version, specialist profile,
blueprint digest, lifecycle state, type-specific specification, and
domain-separated component digest.

Behavior, instruction, knowledge, and tool-policy specifications are checked
against the exact blueprint fields they implement. Runtime manifests declare
a provider-neutral runtime class and explicit execution, network, and process
access flags. The checked-in Passive OSINT fixture uses `disabled_fixture`,
has no provider, model, hosting reference, network access, process access, or
tool admission, and contains no prompt or knowledge corpus.

`candidate-onboarding` reconciles all five component digests against each
candidate artifact and reports missing, mismatched, lifecycle-incompatible,
runtime-incompatible, and orphaned artifacts. A complete contract fixture
does not count as a nonfixture implementation, qualification result, routing
change, deployment, or authority grant.

## Candidate evaluation preflight

Phase 26 binds the Passive OSINT candidate, blueprint, five-component
catalog, deterministic onboarding report, 29-case synthetic suite, eight
qualification gates, and complete review requirements into one
content-addressed submission.

The preflight validator reconstructs the onboarding report, revalidates the
suite, and rejects stale or substituted candidate, component, suite, gate,
or review-policy bindings. A successful fixture preflight reports six passed
contract checks but remains ineligible for authoritative evaluation.

The submission is unsigned, has no reviewer assignments, provides no signed
evidence manifest, and binds only an advisory suite. D008 qualification
decision authority remained pending at Phase 26. Preflight does not run the suite, score
observations, qualify a candidate, change routing, or execute work.

## Approved qualification authority

Phase 31 records explicit repository-owner approval of all seven recommended
D008 options. The decision is bound to the exact Phase 30 dossier and accepts
no alternative authority, trust-root, credential, evidence, routing,
suspension, or revocation option.

The approved contract keeps the reviewed registry as the authoritative
routing source and keeps qualification state out of mutable SQLite runtime
state. It requires offline-verifiable, content-addressed signed evidence and
role-scoped short-lived reviewer credentials rooted in an
organization-owned offline trust root.

Independent Control may issue a signed emergency suspension but cannot grant
qualification or reinstate a specialist. Reinstatement requires full
independent review. Signed registry revisions and releases distribute
suspension and revocation.

The checked decision creates no root, key, credential, reviewer, evidence,
qualification status, registry mutation, routing eligibility, or execution.
It authorizes future implementation of those fail-closed contracts.

Phase 32 defines the signed trust-policy and reviewer credential structures.
The policy binds the approved D008 record and qualification standard, keeps
the root public key outside the policy, and separates reviewer credential,
decision, and revocation key uses. Reviewer credentials bind one reviewer to
one independent role and cannot exceed 30 days.

No live policy, credential, authority key, signature, or reviewer identity is
checked into the registry. Structural parsing alone does not authenticate a
signature.

Phase 33 adds fail-closed cryptographic verification. A policy must verify
against a separately supplied offline root and bind the exact approved D008
record and qualification standard. A reviewer credential must verify against
an authorized non-revoked credential issuer key and match the expected
reviewer, independent role, profile scope, policy digest, and validity
windows. Verification remains in memory and adds no registry or SQLite
mutation.

Phase 34 defines candidate-owner-signed evidence manifests and reviewer
attestations. Each manifest binds the exact policy, standard, candidate,
suite, observation set, report, repository, and every case-evidence object.
Every case requires a candidate result, supporting evidence, and reproduction
material. Each reviewer attestation binds one verified credential and one
verified manifest, rejects self-review, and has no qualification effect.

No live evidence, manifest, attestation, owner key, reviewer key, or
repository enrollment is checked into the registry. D009 tracks how a live
deployment will enroll candidate-owner keys and evidence-repository identity.

Phase 35 defines initial qualification approvals. A decision binds one
verified manifest and the complete canonical reviewer set. Verification
requires at least two distinct technical evaluators, independent Control,
independent Assurance, unique reviewer identities, credentials, and keys,
supporting conclusions, an authorized decision-signing key, and a validity
window no longer than 180 days.

The signed decision has `registry_effect: none`. No checked decision changes
profile status or routing.

Phase 36 defines the separate qualification lifecycle. An initial verified
decision produces sequence 1 active status. Signed transitions bind the
exact prior checkpoint and support suspension, terminal revocation, renewal,
and reinstatement. Restrictive transitions carry bounded content-addressed
causes. Suspension requires a verified independent Control credential.
Revocation requires the separated qualification-revocation authority key.
Renewal and reinstatement additionally require fresh evidence, fresh reviewer
attestations, and a new verified decision after the prior status change.
Every transition retains `registry_effect: none`.

No lifecycle event or status checkpoint is checked into the registry.

Phase 37 defines reviewed qualification registry revisions. It builds one
deterministic in-memory proposal from a verified status checkpoint, requires
credentialed independent Control and Assurance reviews of the exact base and
proposed digests, and verifies an authority signature through the key use
appropriate to the resulting status. Initial qualification requires a
defined specialist. Later revisions require the exact stored predecessor
digest and next sequence number.

Specialist profiles may now carry a structural qualification chain head.
Active maps to `qualified`, suspended maps to `suspended`, and revoked maps
to `revoked`. Existing profiles remain compatible without that optional
record. No checked profile changes in Phase 37.

The verified revision effect is `proposed_registry_only`. The library does
not write the proposal, merge it, publish it, or deploy routing state.
Repository and release review remain the application boundary.

Phase 38 packages D009 into one deterministic, content-addressed decision
dossier. It compares four architecture alternatives and requires nine
explicit choices covering authority, scope, repository identity, review,
rotation, revocation, rollback, lifetime, and locator policy. The recommended
organization-signed enrollment catalog remains `not_selected`. Its effect is
`none`; no owner, key, candidate, or repository is enrolled.

Phase 39 packages D001 through D005 into one deterministic collaboration
authority dossier. It compares four authority models and recommends a
reviewed reconfiguration ledger with a complete five-decision bundle. The
recommendation remains `not_selected`. The current specialist-only,
same-command, one-handoff boundary remains authoritative.

Phase 40 adds a separate development example under
`examples/implementation/passive-osint`. It includes a structured instruction
bundle plus five complete component bindings for
`development.passive-osint`. It is not part of the active registry catalogs.
Provider, model, hosting, retrieval, tools, and execution remain unselected
or disabled.

Phase 41 adds a readable 29-case synthetic evaluation source and its
deterministic hash-only qualification suite beside that development example.
The suite exactly covers the eight planned gates. It has no observations,
results, evidence, qualification effect, runtime access, or catalog promotion.

Phase 42 adds a content-addressed managed API evaluation boundary beside the
Passive OSINT example. It records the selected isolated API architecture while
leaving provider, model, endpoint, region, retention policy, and credential
reference unselected. Its execution flag remains false and its operational
effect is `none`.

## Collaboration planning

Phase 6 uses the registry hierarchy to turn an assembled Joint Mission Cell
into a deterministic CollaborationPlan version 1:

```text
readiness
  -> parallel specialist work
  -> domain commander synthesis
  -> maneuver-group integration
  -> cross-surface integration
  -> parallel Control and evidence review
  -> independent Assurance review
```

Every work item owner and supporter must be an active profile assigned to the
cell, and every assembled profile must receive at least one owner or support
assignment. Specialists own narrow work packages, domain commanders
synthesize selected work in their domains, and group commanders integrate
the represented domains. Shared profiles provide cross-surface coordination,
Control, evidence, and Assurance without taking ownership of specialist
work.

Work item action tiers cannot exceed the mission or owner ceiling, and work
item evidence requirements cannot be weaker than the mission or owner
minimum. Stable IDs, ordering, dependencies, and SHA-256 content bindings
make repeated planning deterministic.

The plan carries the common `mission_objective`; each item carries its
registry-defined `role_mission`. Work item IDs are local to their plan, so a
downstream system must use `(plan_id, work_item_id)`, ingest JSON with
`load_collaboration_plan`, and run `validate_collaboration_plan` against the
exact reviewed registry and mission before scheduling.

The plan is scope-referenced but unsigned. It does not grant authority,
dispatch a model, execute a task, infer capabilities, issue credentials,
persist mutable status, or write SQLite state. The full-Army router is
explicitly mapped to all 348 specialists, but the bundled policy currently
permits only the 20 qualified specialists.

## Validation

Run the authoritative registry validator from the repository root:

```text
python -m sunderkey.cli validate-registry --registry registry/army-v1.json
```

Run the repository content check as part of the same review:

```text
python -m sunderkey.cli check-content --root .
```

Create and validate the collaboration graph from the included mission:

```text
python -m sunderkey.cli plan-collaboration --registry registry/army-v1.json --mission examples/missions/internet-api-to-data.json
```

Create the deterministic full-Army readiness report:

```text
python -m sunderkey.cli army-readiness --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --policy registry/routing-policy-army-qualified-v1.json
```

Create the deterministic qualification coverage report:

```text
python -m sunderkey.cli qualification-coverage --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --standard registry/qualification-standard-v1.json --plans registry/qualification-plans-army-v1.json
```

Evaluate the synthetic advisory fixture:

```text
python -m sunderkey.cli qualification-evaluate --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --standard registry/qualification-standard-v1.json --plans registry/qualification-plans-army-v1.json --suite examples/qualification/passive-osint-suite.json --observations examples/qualification/passive-osint-observations.json
```

Create the deterministic candidate implementation inventory:

```text
python -m sunderkey.cli candidate-inventory --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --standard registry/qualification-standard-v1.json --plans registry/qualification-plans-army-v1.json --blueprints registry/candidate-blueprints-army-v1.json --candidates registry/candidate-implementations-v1.json
```

Create the deterministic specialist candidate blueprint coverage report:

```text
python -m sunderkey.cli candidate-blueprint-coverage --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --standard registry/qualification-standard-v1.json --plans registry/qualification-plans-army-v1.json --blueprints registry/candidate-blueprints-army-v1.json
```

Validate candidate component bindings and onboarding completeness:

```text
python -m sunderkey.cli candidate-onboarding --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --standard registry/qualification-standard-v1.json --plans registry/qualification-plans-army-v1.json --blueprints registry/candidate-blueprints-army-v1.json --components registry/candidate-components-v1.json --candidates registry/candidate-implementations-v1.json
```

Validate the unsigned synthetic evaluation submission:

```text
python -m sunderkey.cli candidate-preflight --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --standard registry/qualification-standard-v1.json --plans registry/qualification-plans-army-v1.json --blueprints registry/candidate-blueprints-army-v1.json --components registry/candidate-components-v1.json --candidates registry/candidate-implementations-v1.json --onboarding examples/qualification/passive-osint-onboarding.json --suite examples/qualification/passive-osint-suite.json --submission examples/qualification/passive-osint-submission.json
```

Create the deterministic specialist implementation roadmap:

```text
python -m sunderkey.cli implementation-roadmap --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --policy registry/routing-policy-army-qualified-v1.json --standard registry/qualification-standard-v1.json --plans registry/qualification-plans-army-v1.json --blueprints registry/candidate-blueprints-army-v1.json --components registry/candidate-components-v1.json --candidates registry/candidate-implementations-v1.json
```

Create the domain commander implementation work packages:

```text
python -m sunderkey.cli implementation-work-packages --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --policy registry/routing-policy-army-qualified-v1.json --standard registry/qualification-standard-v1.json --plans registry/qualification-plans-army-v1.json --blueprints registry/candidate-blueprints-army-v1.json --components registry/candidate-components-v1.json --candidates registry/candidate-implementations-v1.json --roadmap registry/implementation-roadmap-army-v1.json
```

Select one exact implementation wave package:

```text
python -m sunderkey.cli implementation-wave-package --packages registry/implementation-work-packages-army-v1.json --wave-id IW-001
```

Build the Phase 30 D008 qualification authority decision dossier:

```text
python -m sunderkey.cli qualification-authority-dossier --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --standard registry/qualification-standard-v1.json --roadmap registry/implementation-roadmap-army-v1.json --packages registry/implementation-work-packages-army-v1.json
```

Build the approved D008 qualification authority decision record:

```text
python -m sunderkey.cli qualification-authority-decision --dossier registry/qualification-authority-dossier-d008.json
```

Build the Phase 38 D009 candidate enrollment decision dossier:

```text
python -m sunderkey.cli candidate-enrollment-dossier --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --standard registry/qualification-standard-v1.json --authority-decision registry/qualification-authority-decision-d008.json
```

Rebuild the approved Phase 65 D009 decision record:

```text
python scripts/build_candidate_enrollment_decision.py
```

Rebuild the Phase 69 D009 implementation completion report:

```text
python scripts/build_candidate_enrollment_implementation_report.py
```

Rebuild the Phase 70 D009 deployment preparation packet:

```text
python scripts/build_candidate_enrollment_deployment_preparation.py
```

Report the dependency-ordered external deployment inputs without performing
enrollment:

```text
python -m sunderkey.cli candidate-enrollment-deployment-prepare --implementation registry/candidate-enrollment-implementation-d009.json
```

Rebuild the blank Phase 71 deployment worksheet and fail-closed preflight:

```text
python scripts/build_candidate_enrollment_deployment_inputs.py
```

Create a new editable worksheet and assess its documentation completeness:

```text
python -m sunderkey.cli candidate-enrollment-deployment-template-create --preparation registry/candidate-enrollment-deployment-preparation-d009.json --output deployment-worksheet.json
python -m sunderkey.cli candidate-enrollment-deployment-preflight --preparation registry/candidate-enrollment-deployment-preparation-d009.json --worksheet deployment-worksheet.json
```

Phase 72 verifies a complete deployment-specific artifact chain with the
offline `candidate-enrollment-deployment-verify` command. The command requires
the preparation packet, completed worksheet and preflight, public verification
context, D008 and D009 decisions, qualification registry inputs, signed policy,
signer authorization, both reviewer credentials, signed catalog, and a new
receipt output path. Re-run every source check for an existing receipt with
`candidate-enrollment-deployment-receipt-verify`. See the Phase 72 document for
the complete command layout.

Rebuild the Phase 73 D011 checkpoint custody and activation decision dossier:

```text
python scripts/build_candidate_enrollment_activation_dossier.py
```

The equivalent offline CLI command is
`candidate-enrollment-activation-dossier`. The checked dossier records eight
recommended but unselected choices and has no activation effect.

Phase 74 records the repository owner's full recommended D011 approval in
`candidate-enrollment-activation-decision-submission-d011.json` and the
content-addressed result in `candidate-enrollment-activation-decision-d011.json`.
The public record and verification commands preserve the approval boundary:
contract implementation is authorized, while checkpoint persistence, catalog
publication, live enrollment, evidence acceptance, qualification, and routing
remain unchanged.

Phase 75 implements the checkpoint mirror and release ledger data contracts
and publishes `candidate-enrollment-release-policy-d011.json`. The policy can
be rebuilt with `scripts/build_candidate_enrollment_release_policy.py` and
verified with `candidate-enrollment-release-policy-verify`. These contracts
perform no operational writes or catalog promotion.

Phase 76 implements the atomic local checkpoint adapter. The adapter requires
an explicit platform access controller and has no permissive fallback. The
included POSIX controller enforces owner-only access. Windows deployment
requires a separately supplied provider that can prove the selected ACL and
directory durability policy.

Phase 77 implements the controlled release transaction over explicitly
supplied verification, checkpoint, ledger, repository, and clock adapters.
Checkpoint and promotion ledger events bind their exact outcome receipts.
Completion remains unready for live enrollment and authorizes only canary
packet preparation.

Phase 78 implements read-only partial-release assessment and same-digest
dual-control recovery. Missing or corrupt established checkpoints remain
blocked pending a production ledger artifact retrieval adapter. Recovery
completion remains closed to live enrollment.

Phase 79 prepares the checked single-candidate canary packet. The packet names
nine external input groups, eleven activation gates, ten stop conditions, and
the separate go or no-go boundary. It contains no selected production values
and has no activation effect.

Phase 188 publishes `expert-runtime-packs-army-v2.json` and three closed JSON
schemas. The catalog binds every Army v2 specialist and domain commander to
the exact checked source records used to compile its runtime contract. Runtime
packs, execution envelopes, and expert work products are content-addressed and
provider-neutral. They grant no model, tool, network, target, qualification,
review, or authorization effect.

Phase 189 publishes
`schemas/expert-model-execution-custody-v1.schema.json` and implements a closed,
provider-neutral execution and atomic budget-custody contract. Six
content-addressed records bind external authentication proof, authority,
invocation, reservation commit, provider observation, settlement, and receipt
to the exact Phase 162 and Phase 188 inputs. The included in-memory custody and
provider implementations are deterministic, process-local, and nonqualifying.
The contract adds no network client, credential resolver, durable backend, tool
effect, target operation, qualification, routing, or authorization effect.

Phase 190 publishes
`schemas/collaboration-plan-replacement-readiness-v1.schema.json` and
`schemas/collaboration-plan-replacement-preparation-v1.schema.json`. The first
describes the snapshot-consistent readiness record over the active plan,
durable high-water provenance, five source snapshots, work state, and drain
requirements. The second binds that exact readiness record to the verified
authority plan, principal-identity upgrade, and optimistic plan version. These
schemas are structural boundaries. Readiness, preparation, signed credentials,
and commit receipts are store-specific mission artifacts and are not checked
registry evidence. Phase 190 adds no network, target, tool, qualification,
routing, or authorization effect.

Phase 191 publishes `schemas/expert-workspace-definition-v1.schema.json`,
`schemas/expert-workspace-lease-receipt-v1.schema.json`, and
`schemas/expert-workspace-acceptance-receipt-v1.schema.json`. The schemas
describe the content-addressed workspace, explicit lease and fencing receipt,
and immutable product-acceptance receipt for the Phase 188 expert runtime. The
dedicated SQLite reference adapter preserves assignments, dependencies,
reviewer requirements, execution envelopes, products, commander lineage,
disagreements, and append-only events with exact schema, storage-type, and
canonical-JSON verification. These records grant no model, provider, network,
target, tool, authorization, qualification, or review effect.

Phase 192 publishes `schemas/semantic-completion-retry-v1.schema.json`. The
schema describes content-addressed completion requirements, evidence,
requirement dispositions, semantic assessments, retry authority, replay commits,
and retry receipts. Runtime validation additionally requires exact Phase 188 and
Phase 189 object identity, one complete execution chain, relevant changed
conditions, bounded attempts, current budget capacity, cooldown, and exact prior
retry lineage. The included replay fixture is process-local and nonqualifying.
These records do not authenticate production authority, dispatch a retry, mutate
budget, call a provider, execute a tool or target action, claim independent
review, change qualification, or grant authorization.

Phase 193 publishes
`schemas/authenticated-expert-model-execution-v1.schema.json`. The schema
describes the strict public admission and dispatch records for authenticated
model execution custody. Runtime validation additionally binds the exact signed
principal, current durable trust, scope and revocation state, active plan,
assigned work, runtime catalog and pack, execution envelope, route, capability,
reservation, budget, provider observation, work product, settlement, and
terminal receipt. SQLite schema version 31 atomically consumes assertion and
replay identities, reserves and settles budget, and preserves immutable
dispatch and event custody. The reference implementation includes no provider
network client, credential resolver, target or tool effect, qualification,
review, or deployment authority.

Phase 194 publishes `schemas/expert-review-record-v1.schema.json`,
`schemas/authenticated-expert-review-registration-v1.schema.json`, and
`schemas/expert-workspace-closure-application-v1.schema.json`. The schemas
describe the closed review snapshot, submission, authenticated receipt,
closure request, closure certificate, closure revocation, authenticated
snapshot registration, and workspace projection receipt records. Runtime
validation additionally binds the exact current mission, plan, workspace,
runtime catalog, expert registry, scope, authority and evidence snapshots,
accepted products, command lineage, dependencies, disagreements, reviewer
roles, signed principal assertions, and replay identities. MissionStore schema
version 32 preserves normalized append-only custody and exact projection
receipts. These records do not perform a review, call a model or provider,
resolve a credential, execute a network, target, or tool action, claim
qualification, select D014 infrastructure, or grant expanded authority.

Phase 195 publishes
`schemas/executable-action-resolution-v1.schema.json`,
`schemas/authenticated-action-admission-v1.schema.json`,
`schemas/action-authority-contracts-v1.schema.json`,
`schemas/action-authority-material-snapshot-v1.schema.json`,
`schemas/action-authority-observation-v1.schema.json`, and
`schemas/authenticated-action-authority-publication-v1.schema.json`. The
schemas close typed catalog, parameter, target, proposal-resolution, quorum,
admission, revocation, authority-source, material-snapshot, observation, and
publication records. Runtime validation additionally binds exact current
mission, plan, trust, scope, review, workspace, execution session, fence,
credential, health, deployment, monitor, safety, catalog, target, and stable
six-axis budget authority. MissionStore schema version 33 preserves normalized
append-only authority publication, resolution, admission, revocation, budget,
and execution-consumption custody. These records do not dispatch an adapter,
perform a network, target, or tool action, establish live target authority,
claim qualification, select D014 infrastructure, or prove deployment.

Phase 196 publishes
`schemas/authenticated-action-execution-v1.schema.json`. The schema describes
closed execution requests, claims, authority consumption, reservations,
dispatch attempts, terminal records, and independent reconciliation intent.
Runtime validation additionally binds the exact Phase 195 receipt, current
mission and plan, trust, scope, roles, review and workspace prefixes, every
action source head, execution session, fence, credential, health, deployment,
monitor, safety, and six-axis budget lineage. MissionStore schema version 34
preserves immutable claim and dispatch checkpoints, predispatch abort,
terminal, closure, reconciliation, and settlement custody. The repository
reference callable and signing fixtures are nonqualifying. These records do
not provide a production adapter or reconciler signer, prove one external
transport attempt, establish target authority, select D014 infrastructure,
claim qualification, or prove deployment.

Phase 197 publishes `schemas/orchestration-journal-v1.schema.json` and a
deterministic OpenAPI document. The registry schema covers content-addressed
orchestration records, typed Phase 196 handoff intent, one-attempt worker
custody, quarantine, terminal observation, independent reconciliation,
source-bound projections, and tenant event chains. The API accepts only
reference and digest bindings for action execution and exposes no worker or
reconciliation mutation endpoint. Phase 196 remains authoritative for action
execution and budget settlement. These records do not provide a production
listener, worker, reconciler signer, adapter, credential resolver, network or
target effect, qualification, deployment authority, or D014 selection.

Release 0.278.0 publishes the Phase 198A
`schemas/target-health-custody-v1.schema.json`. The schema
closes pinned trust roots, root-signed collector policy revisions and
exact-policy revocations, collector-signed custody envelopes, restart-safe
signing contexts, verification results, acceptance receipts, and chained
custody events. The file-backed SQLite reference store preserves immutable
transition history and reconstructible heads. Historical verification proves
the exact policy, revocation state, predecessor, and trusted acceptance time
for each stored envelope without granting current authority. Live verification
and replay-for-use separately enforce current root and policy validity,
evidence freshness, exact durable heads, and scheduled revocation cutoffs. An
effective revocation is terminal only for its exact policy revision; recovery
requires a contiguous root-signed successor with a new collector epoch and
distinct key. The schema and store provide no collector, private key, network
or target access, MissionStore mutation, pause or resume decision, control
effect, qualification, deployment authority, or D014 selection. D014 and
WQ-016 through WQ-022 remain external and unchanged.

Release 0.279.0 adds the Phase 199 content-addressed current-head binding and
atomic read-only inspection. One inspection binds the verified SQLite store
identity, global transition high-water, pinned root, current policy, optional
revocation, signed envelope, custody receipt, custody event, and current
verification from one read transaction. The serialized record is a
content-closed description, not a signed or independently authenticated
attestation of SQLite provenance. It does not classify target health, grant
authority, admit or execute an action, reserve capacity, enforce a pause or
resume, contact a target, or select production infrastructure. Positive use
still requires a fresh inspection from the configured custody store and every
separate live authority, admission, reservation, and execution gate. D014 and
WQ-016 through WQ-022 remain external and unchanged.

Release 0.280.0 publishes
`schemas/target-health-gate-v1.schema.json`, the closed Phase 199B Python
contracts, and MissionStore schema version 35. The records bind one exact
target latch to current health observations, guarded state transitions, two
qualifying recovery observations, and a separately authorized independent
Control resumption. The release includes no Phase 199C store service, live
collector, admission or executor enforcement, authority consumption, network
or target effect, qualification, deployment authority, or D014 selection.

Release 0.281.0 adds the Phase 199C transaction-scoped MissionStore service.
Fresh current inspections drive durable healthy or adverse observations, and
an adverse result commits the pause latch before denial is returned. Recovery
preparation is read-only. Resume atomically consumes a current approved
independent Control assertion, replay identity, operation intent, and
authority-use sequence. Historical verification validates immutable gate
custody but cannot establish live currentness. Resume is live-current only and
rejects consumed assertions, operation intents, and replay identities even on
an exact retry. It never returns historical custody as a positive result. The
release does not integrate Phase 195 admission or Phase 196 execution, enforce
executor pauses, collect live health, perform network or target effects, claim
qualification, deploy a service, or select D014 infrastructure.

Release 0.282.0 adds the Phase 199D transaction-scoped Phase 195 integration.
Positive authority publication, admission, replay for use, and current receipt
verification require a new context-bound health decision and preserve its
exact immutable use in MissionStore schema version 36. A valid adverse result
commits its pause transition before denial. The migration baseline identifies
older action records as not health gated and never interprets them as permits.
Historical verification cannot establish current eligibility. The release
does not integrate Phase 196 execution, enforce executor pauses, collect live
health, perform network or target effects, claim qualification, deploy a
service, or select D014 infrastructure.

Release 0.283.0 adds the Phase 199E authenticated execution health gate in
MissionStore schema version 37. Claim, dispatch, final invocation, and terminal
replay for use require fresh current action authority and target health. An
adverse final decision commits the pause before exact zero call settlement.
Committed invocation authorization prevents automatic redispatch after a
crash. External adapter fencing, live collection, qualification, deployment,
and D014 selection remain separate requirements.

Build the Phase 39 collaboration authority decision dossier:

```text
python -m sunderkey.cli collaboration-authority-dossier --registry registry/army-v1.json --capabilities registry/capabilities-army-v1.json --policy registry/routing-policy-army-qualified-v1.json
```

Build the Phase 40 Passive OSINT development example:

```text
python scripts/build_passive_osint_development_candidate.py
```

Build the Phase 41 Passive OSINT evaluation suite:

```text
python scripts/build_passive_osint_evaluation_suite.py
```

Build the Phase 42 managed API evaluation boundary:

```text
python scripts/build_managed_api_evaluation_boundary.py
```

The registry loader rejects unsupported fields, malformed identifiers,
duplicate values where uniqueness is required, broken hierarchy
references, count mismatches, and non-ASCII catalog content.

## Change process

For a catalog update:

1. Preserve existing identifiers unless a role is being replaced.
2. Update hierarchy records and profile references together.
3. Reconcile every value in `count_contract`.
4. Increment `catalog_version` for an accepted catalog revision.
5. Validate the registry and run the complete test suite.
6. Review policy, safety, and pilot impacts before release.

Do not place credentials, target details, operational payloads, or
engagement evidence in the registry. Those belong in scoped mission and
evidence systems with their own access controls.
