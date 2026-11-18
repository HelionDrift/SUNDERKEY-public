# Bounded offline GCS catalog mapping

This module maps the existing D012 `ImmutableCatalogObjectProvider` through an
explicit caller-injected synthetic transport. It supplies no Google client,
SDK, network transport, default backend, credentials, filesystem storage,
deployment, catalog publication, evidence ingestion or activation authority.
Its environment is fixed as `reference_simulation_nonqualifying`.

The separate [inert catalog wire codec](gcp-gcs-catalog-wire-offline.md)
describes these stable object IDs and decodes bounded supplied response bytes.
It supplies no transport or authenticated provider observation and preserves
this mapping's original finite horizon and process-local restart limits.

## Existing port and exact object identity

`GCSImmutableCatalogObjectProvider` implements `put_sha256_object` and
`read_sha256_object` with the existing D012 request, receipt and exact
`immutable_catalog_overwrite` rejection families. The physical key is stable
`catalog/{object_id}`. Each descriptor binds the independent SHA-256, byte size,
namespace and failure domain. The common suite requires rejection when one
object ID is reused with different truthful content; it does not require the
digest in the physical name. A digest-only path must not silently accept that
collision as a new object or turn an object ID into a mutable latest alias.

Writes are create-only, with generation precondition `0` and no metageneration
precondition. Existing-object replay requires the exact descriptor and payload.
A failed create precondition requires a confirmed pinned read before it can
be classified as replay or the exact request/subject-bound collision rejection.
An absent or contradictory acknowledgement is not expected policy evidence.

Metadata confirmation pins both generation and metageneration, exact bucket,
stable name, descriptor, byte size and fixed-horizon protection. Pinned bytes
must reproduce the descriptor's SHA-256. Provider generation is not a logical
SUNDERKEY revision or a cryptographic content digest. Editable metadata alone
does not prove the bytes, provider origin or permanent immutability.

## Required finite simulation profile

The constructor requires `GCSCatalogSimulationProfile`, `GCSCatalogTransport`
and a native aware UTC clock. The profile contains explicit catalog and ledger
bucket, namespace, failure-domain and account-reference declarations. All four
must be distinct. These labels do not authenticate GCP ownership, independent
administrators, effective inherited IAM, credentials or failure domains.

The immutable profile also binds `simulation_started_at`,
`simulation_use_until` and a positive bounded retention duration. The fixed
window must fit the declared duration. No current-time default or inferred
deployment lifetime exists. Profile exports are detached and content-bound;
the mapping captures its own profile and original digest.

Every positive operation requires an active window and complete current bucket
evidence matching the profile and the requested UTC instant. The supported
subset uses locked bucket retention, disabled versioning, no default
event-based hold and no object-level retention configuration. Every object
must be current, without temporary or event-based holds, in `bucket_policy`
mode, with observed retention covering the original fixed use horizon.
Unsupported, missing, stale, shorter or substituted observations fail closed.

Use is forbidden at or after `simulation_use_until`, including creation when
the live object is absent. A longer observed retention does not extend the
source horizon. Replay does not restart its duration. This is a finite
reference-model protection window, not everlasting immutability, production
Bucket Lock evidence or fulfillment of D011's
`deployment_lifetime_plus_audit_period` requirement.

## Ownership, ambiguity and remembered versions

The catalog-specific bucket/object observations, read envelopes and write
envelopes are frozen typed values. Exact native strings, integers, booleans,
bytes and UTC datetimes are required. At every boundary, fixed typed families
and their nested descriptors are reconstructed into owned copies. This does
not extend or change the existing ledger/head or GCS wire conventions.

Transport read and write requests have separate deep-owned delivery copies and
unexposed exact native field snapshots. The declared request is rechecked after
every callback before consuming success, create-conflict reconciliation or any
error path. Native-alias, descriptor, request-ID, payload or precondition mutation
does not produce a positive receipt or a fabricated expected policy rejection.
These checks cannot reverse an already applied provider write.

The mapping retains a bounded process-local witness of each positively
confirmed descriptor and version. A witnessed identity disappearing or
reappearing with changed coordinates, generation, metageneration, retention or
descriptor fails. This witness contains metadata, not raw catalog bytes. It
is neither a durable ledger nor restart custody. A new instance cannot infer
historical absence from a live-object lookup, prove every past version, or
authenticate an observation. Those limits remain explicit.

An ambiguous write raises an unconfirmed error without automatic retry. It
may already have been applied. The caller can explicitly reconcile the exact
same request inside the unchanged window; no error implies rollback. Postwrite
bucket and time checks must also pass before a positive receipt is returned.
The mapping provides no cross-object transaction, release-audit sequence,
signed release head, rollback recovery decision, D013 accepted receipt,
hold/release transition or deletion operation.

Local bounds are 16 MiB per object, 4,096 confirmed identities per mapping
instance, 128-character public identifiers, and positive signed-long provider
tokens. Bounds reject unsupported input before hashing or transport invocation
where possible. These are software-model limits, not Google service limits.
An injected Python transport can perform arbitrary actions; its environment
label is not attestation. Only inert synthetic transports are supplied by the
tests. The module creates no backend or authenticated provider receipt.

## Verification and remaining production boundary

Run `python -B -m unittest tests.agents.test_gcp_gcs_catalog -v` with
`PYTHONPATH=src`. Unit checks include exact creation/replay/read, collision,
generation and metadata substitution, native aliases, source mutation, absent
and recreated versions, unsupported holds, protection expiry, ambiguous writes,
create races, bounded objects and detached ownership. The composition fixture
uses three GCS-mapped ports and five existing reference ports, executing the
same twelve ordered D012 cases. Existing reference checkpoint fixtures use
temporary local files; they are not a selected production ACL deployment.

The complete reference-composition fixture additionally substitutes the bounded
audit chain for the old audit stub, with independent synthetic audit custody
coordinates. It runs the same unchanged twelve-case suite and checks audit
failure/signing block, lost acknowledgement uncertainty, cold replay and
separation from release-head state. The signer remains a simulated digest
fixture, not approved production signing bytes or a real release signature.

The report remains nonqualifying simulation evidence and requires independent
review. Passing it does not prove real retention, deletion denial, durable
restart recovery, availability, IAM, account separation, authenticated runner
provenance or live custody. D014 selections, exact deployment and audit periods,
named custodians, independent failure-domain evidence, signing protocol,
release-audit sequencing, production conformance and separate dual-control
go/no-go remain blocked. No lifecycle, retention-lock or deletion setting is
applied to any resource.

See the existing D012 interface and common suite,
[two-port GCS mapping](gcp-gcs-custody-offline.md) and
D014 planning boundary.
