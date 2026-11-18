# GCP acceptance checklist, offline only

`sunderkey.gcp_acceptance_checklist` composes an unsigned, content-addressed
checklist from an exact GCP resource binding plan and explicitly supplied
existing prerequisites. It does not collect observations, run probes, install
software, contact a provider, access credentials, sign records, admit a backend,
or accept a deployment.

This leaf API is preparatory software, not a runtime adapter or an operator
command. All authority, network, credential, runtime, storage, deployment and
qualification effects remain `none`. Every service is `required_not_observed`.
`observed_live_acceptance` and `qualified_readiness` are always false.

## Explicit inputs

`build_gcp_acceptance_checklist(plan, *, prerequisites, host_declarations,
dossier, deployment_profile, regional_binding)` first calls the existing
`verify_gcp_resource_binding_plan`. The exact dossier, deployment profile and
regional binding must reproduce the plan's source bindings. A complete signed
D014 selection is still required outside this composer. Declared GCP `us-west3`
coordinates are not proof that resources exist or are configured.

`GcpAcceptancePrerequisites` requires these existing source families:

| Source | Existing contract replay | Checklist boundary |
| --- | --- | --- |
| PostgreSQL deployment manifest | `DeploymentManifest` checked template | Self-managed deployment, migration, pinned images, backup, restore, rollback, TLS, egress, health and cleanup evidence |
| Containment suite catalog | `ContainmentConformanceSuiteCatalog` current producer | Exact 18 OCI and 20 microVM probe IDs, no passing observations |
| Explicit backend/host pairs | `GcpContainmentPrerequisite` with `ContainmentBackendAttestation` and `ContainmentBackendDeploymentBinding` | Existing binary/configuration bundles and read-only host preflight checks, not observed host capabilities |
| PostgreSQL capability declaration | `postgresql_production_capabilities` | Atomic batches/outbox, isolation, fencing, idempotency and tenant boundaries, not an open database |
| Browser policy | `AuthorizedBrowserPolicy` and exact `ExecutionBinding` | Action, navigation, output and timing limits, not a signed scope/admission or browser driver |
| OIDC trust policy | `SsoTrustPolicy` | Issuer, audience, tenant, MFA and time policy, not an authenticated keyset or token |
| Health definitions | `ProbeDefinition` and exact `HealthContext` | Liveness, readiness, dependency and integrity definitions, not observations or permission to resume |

Every source is captured as detached native JSON with its identifier and exact
canonical document hash. Existing parsers and producers revalidate the supplied
records. Exact source classes are required. Missing required source families,
subclasses, duplicate containment classes, non-native keys/scalars, boolean
counter aliases, unsupported manifests, stale source hashes and inconsistent
wrapper metadata fail closed. An empty containment-pair tuple is allowed only
as an explicit missing declaration and adds a blocker for each missing class.
Missing required health kinds or an SSO policy without required MFA likewise
remain named blockers; no policy is invented as a fallback.

Declared contexts must also join across those independently valid records. The
SSO trust policy tenant, browser `ExecutionBinding` tenant and health-context
tenant must equal the exact revalidated `TenantRegionBinding.tenant_ref`. The
health-context worker must equal the revalidated `DeploymentProfile.worker_ref`,
and all health definitions must retain one exact context. A separately valid,
content-addressed policy or definition for another tenant or worker is rejected.
Reconstructing a consistent alternate deployment requires its own exact resource
plan source bindings and does not make an earlier checklist current. These are
declaration comparisons, not authenticated tenant identity, worker admission,
mission authority or observed health. Existing source enum fields and typed
collections are checked before serialization; a custom `.value` object cannot
normalize into an accepted enum declaration.

## Host declaration and compatibility blockers

`host_declarations` is an exact native object with `oci_container` and `microvm`
keys. Each value is explicitly `null`, or an exact object with all `HOST_FIELDS`:
`project_id`, `instance_name`, `zone`, `machine_type`, `os_image`,
`os_image_sha256`, `architecture`, `host_id`, `service_identity_id`,
`service_account_ref`, `kernel_image_sha256` and `rootfs_image_sha256`.

Unknown values must be explicitly null. They remain named missing-coordinate
blockers. OCI kernel/rootfs fields must be null; microVM declarations require
both pinned digests. OS images use an exact
`projects/PROJECT/global/images/IMAGE` declaration, not a moving image family.
Projects and service-account references must occur in the resource plan, zones
must remain within `us-west3`, and declared host identity/architecture must agree
with any supplied deployment binding. These are declaration comparisons, not
Google API validation or proof of machine, image, KVM, Linux, rootless Podman,
Firecracker, networking or service identity compatibility.

Even completely filled host declarations retain
`provider_host_capabilities_unverified` and
`host_preflight_observations_missing`. Missing machines, images, zones, exact
host components and signed live observations cannot be replaced by synthetic
test values. Cloud SQL coordinates retain
`managed_sql_manifest_mapping_required`: the existing single-node/HA
PostgreSQL manifests describe self-managed PostgreSQL. Selecting Cloud SQL does
not make their service, volume, quorum, migration or restoration assumptions
compatible with a managed service.
The owner has since retained the self-managed design, so Cloud SQL coordinates
are not acceptance evidence for the current D014 database choice. The
self-managed mapping preserves the
separate host, failover, fencing, and recovery evidence requirements.

## Required evidence and dependency order

Six rows name positive and negative evidence for OCI, microVM, browser,
PostgreSQL, identity and health. Containment rows retain the existing probe IDs
and host-check names. Required negatives include metadata, host credential and
network denial, deadline/cancel stop, output overflow, workspace/container/VM
residual cleanup, browser scope/origin/budget/file boundaries, database rollback
and stale writers, OIDC key/claim/time/replay failures, and fail-closed health
pause. Recovery eligibility is not resume authority; authenticated identity is
not operator authority. Every row requires content-addressed receipts, bounded
redacted runtime outputs, stop outcomes and cleanup/residual evidence.

The existing queue order remains:

1. WQ-016: exact read-only host preflight, retaining its WQ-015 dependency.
2. WQ-017: signed complete OCI/microVM dynamic conformance after WQ-016.
3. WQ-018: signed execution evidence for six reference candidates after WQ-017.
4. WQ-019: distinct domain commander, Control and Assurance qualification
   decisions after WQ-018.

All four gates are false and blocked on external evidence. Checklist coverage
cannot bypass any queue dependency, manufacture a reviewer decision, declare
live readiness, or approve later shadow/canary/routing work.

## Integrity and bounded use

`GcpAcceptanceChecklist.from_dict` checks canonical content integrity and fixed
non-authority boundaries. It is not current-source verification or historical
runtime replay. `verify_gcp_acceptance_checklist` requires the original explicit
plan, prerequisites, host declarations and plan sources, reconstructs a fresh
checklist, and compares canonical JSON. Readdressing a substituted source or
checklist does not make it reproduce the supplied current sources.

Inputs and outputs use native JSON primitives only, printable ASCII strings,
signed 64-bit integers, a depth bound of 24, at most 50,000 nodes and 4,096 entries
per object/list, at most 64 health definitions, and at most 1 MiB per checklist.
Aggregate canonical JSON bytes, including punctuation and string escapes, are
charged during the bounded walk before serialization. Shared-list/string graphs
cannot expand beyond the byte limit in `json.dumps`. Source JSON is bounded
before parsing. Outputs are detached; modifying an
exported dictionary does not change a plan, prerequisite, checklist or later
verification result. Import and composition perform no file or runtime I/O.

The deterministic regression inputs are synthetic, reference-only and
nonqualifying. They are not GCP resources, host observations, provider
credentials, target permissions, accepted ingest controls or qualification.
