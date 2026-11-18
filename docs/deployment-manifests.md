# Deployment Manifests

`sunderkey.deployment_manifests` publishes a deterministic, content-addressed
bundle for three deployment profiles:

- local SQLite and ASGI;
- single-node PostgreSQL; and
- high-availability PostgreSQL.

The checked bundle is
`registry/deployment-manifest-bundle-v1.json`. The corresponding JSON Schema is
`registry/schemas/deployment-manifest-bundle-v1.schema.json`.

## Boundary

The builder produces repository data only. It does not deploy services, inspect
a host, read credentials, open a network connection, run a process, invoke a
container runtime, execute a database migration, or qualify an environment.
The bundle reports repository publication as complete while live deployment and
external qualification remain infrastructure-blocked.

All credential inputs are opaque `secretref:` values. Images use registry
qualified references with exact SHA-256 digests and separate exact versions.
No moving tags are accepted. Every service has a stable workload identity, runs
as a non-root identity, and uses a read-only root filesystem in the declared
template.

## Contract bindings

Each profile binds the exact repository identities for the customer-hosted
deployment profile and the SQLite and PostgreSQL persistence capability
declarations. It also binds versioned contract fingerprints for:

- egress proxy admission and enforcement;
- health-state aggregation and recovery admission;
- high-availability quorum, epoch, and fencing coordination; and
- regional custody, retention, and transfer admission.

The PostgreSQL profiles also bind the checked PostgreSQL adapter migration ID,
version, and SHA-256. A deployment operator must still execute and observe the
migration through an independently controlled environment.

## Profiles

| Profile | Persistence | Ingress | Egress | Coordination |
| --- | --- | --- | --- | --- |
| Local SQLite and ASGI | One operator-managed SQLite volume | Loopback only | Deny all | One durable scheduler lease |
| Single-node PostgreSQL | One encrypted durable PostgreSQL volume | TLS proxy only | Default-deny allowlist proxy | One active scheduler with durable lease and fence |
| High-availability PostgreSQL | Three encrypted durable PostgreSQL volumes | Redundant TLS proxies | Redundant default-deny allowlist proxies | Three voters with quorum, leader epoch, and fencing token |

The local profile has no secret references, no public ingress, and one worker.
The single-node profile adds separate API, worker, scheduler, database, ingress,
egress, backup, and operator-invoked migration roles. The high-availability
profile increases control-plane, scheduler, worker, database, ingress, and
egress replicas while requiring same-region replication and fail-closed quorum
handling.

## Security posture

The manifest encodes these defaults:

- no public ingress;
- loopback-only local access or TLS-only ingress;
- mutual TLS for non-local service traffic;
- deny-all local egress or an explicit allowlist proxy;
- exact image digests and versions;
- non-root service identities and read-only root filesystems;
- no automatic migrations or rollbacks;
- no automatic database restore;
- separate migration, backup, rollback, and cleanup evidence;
- same-region key and data custody;
- cross-region transfer denied by default;
- stale writer rejection and fail-closed ambiguous coordination; and
- separate recovery admission after unhealthy or uncertain state.

## Operations represented by the manifest

The profiles describe, but do not perform:

- durable scheduling and worker concurrency;
- atomic outbox delivery;
- PostgreSQL migration preflight and backup;
- continuous archiving and point-in-time recovery for PostgreSQL;
- liveness, readiness, dependency, and integrity probes;
- regional custody and retention policy enforcement;
- quorum, epoch, and fencing behavior for high availability;
- image digest rollback; and
- temporary volume removal and residual cleanup verification.

Database drop is forbidden by every cleanup profile. Rollback requires a prior
manifest reference and explicit database restore approval. Runtime health does
not resume target actions by itself.

## External evidence required

Repository publication is not deployment proof. Qualification requires external
evidence appropriate to the selected profile. The complete production set is:

- backup restore drill receipt;
- capacity load test receipt;
- cleanup residual scan receipt;
- egress enforcement observation;
- health probe observation set;
- migration execution receipt;
- regional custody attestation;
- rollback drill receipt;
- runtime image signature verification; and
- TLS handshake observation.

The local profile omits production-only network, capacity, custody, and backup
evidence, but it still requires migration, rollback, cleanup, health, and image
verification evidence. Evidence collection, admission, authorization, and
qualification are separate workflows.

## Verification

`build_deployment_manifest_bundle()` always returns the same three profiles in
the same order. Each profile and the bundle have domain-separated SHA-256
identities. `DeploymentManifestBundle.from_dict()` rejects unknown fields,
changed templates, image drift, secret values, identity drift, and content hash
drift. `parse_deployment_manifest_bundle()` additionally requires canonical
ASCII JSON.

Profile templates and complete bundles are compared as canonical JSON, not
Python mapping equality. Native boolean, integer and floating-point aliases
cannot preserve a prior address or change the checked template through
readdressing. Valid IDs and checked registry bytes remain unchanged. See
[offline deployment manifest integrity](offline-deployment-manifest-integrity.md)
for the replay controls and their limits.

The test suite rebuilds the bundle, compares it to the checked registry file,
validates it against JSON Schema Draft 2020-12, verifies each security posture,
and confirms that the module exposes no runtime, host discovery, container,
network, or subprocess surface.
