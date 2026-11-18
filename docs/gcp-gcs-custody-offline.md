# Offline GCS custody mapping

This slice maps five existing D012 operations through a caller-injected
transport. It supplies no network transport, Google SDK, credentials, project
discovery, bucket creation, retention locking, IAM changes, or deployment.
It does not complete D014 or turn the `us-west3` planning assumption into
operational authority.

## Supported ports and explicit inputs

`GCSRetentionLockedLedgerObjectProvider` implements `put_if_absent`,
`read_verified`, and `read_retention_state`.
`GCSConditionalLedgerHeadProvider` implements `read_head` and
`compare_and_swap_head`. Both preserve the existing D012 request and receipt
families. Exact typed families, native scalar fields, nested descriptors,
digests, and status/verification flags are reconstructed at use.

Read and write callbacks receive separately owned requests. Exact native field
snapshots remain unexposed to the transport and are checked again before any
successful result, generation-conflict reconciliation, ambiguous write or other
error is interpreted. Late mutation cannot redefine the original request,
preconditions or acknowledged operation. A changed callback request yields no
positive receipt; this check cannot undo a write already applied externally.

The constructor requires an explicit `GCSCustodyProfiles`, injected
`GCSCustodyTransport`, and aware UTC clock. The profiles declare bucket names,
namespace references, failure-domain references, versioning settings, locked
retention settings, and retention durations. Names and references are inputs,
not independently verified cloud ownership or failure-domain separation.
No profile is inferred from a region or an environment variable.

The supported subset requires a locked ledger bucket with positive retention,
versioning disabled, and a distinct namespace and bucket for unlocked,
zero-retention head objects. Observed bucket profiles must match the declarations.
Unsupported profiles fail before a transport write. Immutable ledger requests
must fit the declared retention duration, match the namespace and failure-domain
references, and bind exact bytes, size, and SHA-256. The offline object-size
limit is 16 MiB; the canonical five-field head limit is 4096 bytes.
The initial bucket-name subset uses 3 to 63 lowercase letters, digits, and
hyphens. Transport timestamps are normalized, second-resolution UTC values;
unsupported names or observations fail closed rather than use a fallback.

## Generation and retention mapping

Ledger writes use `ifGenerationMatch=0`. Replay requires a confirmed, identical
descriptor and digest-verified pinned object. A `412` alone is not success or
evidence of an immutable-overwrite denial. Confirmed conflicting content yields
the existing exact request/subject-bound `immutable_ledger_overwrite` rejection.

Head writes use `0` for initial creation, or the observed generation and
metageneration for a subsequent CAS. The logical ledger sequence remains a
SUNDERKEY field, not a provider generation number. Forks, stale predecessors,
gaps, and rollback attempts remain rejected. Every byte read pins both observed
tokens, revalidates metadata coordinates, and verifies the resulting bytes.
Heads must reproduce the canonical JSON document and deployment binding.

The mapping rejects noncurrent observations. GCS create-only preconditions
describe absence of a live object, not absence of all historical versions;
this is why versioning-enabled profiles are outside the initial supported
subset. See [Google request preconditions](https://docs.cloud.google.com/storage/docs/request-preconditions).

The ledger profile is bucket-retention based. Sufficient active expiry and
matching locked bucket observations are required before a verified retention
receipt is returned. Retention and byte checks use injected observations, not
authenticated environmental proof. A retention-state read must also fit the
original descriptor's declared deadline; a longer observed duration cannot
silently upgrade that source binding. A different prefix would not exempt a head
from bucket retention, so heads use a separate bucket. See
[Google Bucket Lock](https://docs.cloud.google.com/storage/docs/bucket-lock).

Editable metadata is not retained immutable content. The adapter checks
descriptor consistency, actual SHA-256 bytes, exact coordinates and metadata
tokens, and observed retention. It does not substitute ETag, MD5, CRC32C, or
custom metadata for the content digest. See the
[Google object reference](https://docs.cloud.google.com/storage/docs/json_api/v1/objects).

`GCSAmbiguousWrite` produces an unconfirmed module error and no automatic retry.
The caller may explicitly replay after deciding to reconcile. A write may have
been applied before a lost acknowledgement; failure is not a rollback claim.
Transport failures are not converted into expected provider policy denials.
There is no cross-object transaction spanning entry creation, head update,
signing, catalog publication, or audit. See
[Google consistency guarantees](https://docs.cloud.google.com/storage/docs/consistency).

## Reference conformance and remaining boundaries

The deterministic test transport composes these two ports with six existing
reference ports and executes all twelve unchanged D012 cases. The report is
`reference_simulation_nonqualifying`, with independent review required and no
provider-selection, qualification, deployment, catalog-publication, enrollment,
or runtime effect. This proves synthetic mapping behavior only, not selected
GCS enforcement, availability, durable restart recovery, IAM isolation, or
authenticated runner provenance. The transport interface itself cannot prevent
arbitrary caller-supplied Python code from performing external actions.

A separate complete composition also combines the GCS ledger, head and catalog
mappings with the reference audit chain across the same twelve unchanged cases.
The audit chain uses dedicated synthetic custody coordinates, not the release
head's bucket, namespace or deployment ID. Audit failure still blocks signing,
including lost acknowledgements after an applied synthetic write. This is
additional reference-composition coverage, not production conformance or a
cross-object transaction.

No immutable-catalog success or D013 accepted-ingest surface is supplied.
D013 accepted receipts assert six controls; an upload cannot by itself prove
envelope encryption, quarantine, retention, residency, immutable versions, and
conditional creation. Existing signed repository-principal authentication
remains separate. Hold/release transitions, every-version cryptographic erasure,
replica/backup key coverage, signed tombstones, durable custody reconciliation,
and live conformance require later explicit work and authority. Retained objects
can also constrain CMEK destruction, so erasure deadlines must be reconciled
with retention before operational selection. See
[Google Object Retention Lock](https://docs.cloud.google.com/storage/docs/object-lock).
