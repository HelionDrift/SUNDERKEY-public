# Durable artifact recorder

The durable artifact recorder is a repository-only adapter boundary for
content-addressed artifact metadata. It converts one admitted artifact
recording request into an exact `TransactionBatch` from the persistence port
contracts and validates the observation returned by an injected adapter.

This increment does not accept artifact bytes or filesystem paths. It does not
open a database, execute SQL, access the network, grant authority, or qualify a
storage deployment. The caller remains responsible for authority, admission,
credential custody, and selecting a suitable persistence adapter.

## Recording request

`ArtifactRecordingRequest` binds all metadata to one tenant, assessment, and
scope. The nested artifact record carries an opaque artifact reference, a
SHA-256 content address, normalized media type, bounded size, retention class,
custody reference, and the prior custody entry content address when one exists.

The request also includes:

- expected artifact and custody aggregate versions
- one fence resource, token, and epoch
- one idempotency key
- one canonical recording timestamp
- an optional atomic outbox event with its own expected version

Artifact size is metadata and is capped at 8 GiB. The module neither receives
nor verifies the corresponding bytes. A content digest returned by the adapter
is therefore checked against the requested content address, but the receipt is
not independent proof that the bytes exist or remain recoverable.

## Deterministic transaction plan

`plan_artifact_recording` creates an `ArtifactRecordingPlan`. The plan contains
the original request and a serializable persistence transaction batch. The
batch has append operations for artifact metadata and custody linkage. If an
outbox event is present, the batch also contains the matching outbox enqueue
operation and event reference.

All aggregate references and operation references are derived deterministically
from opaque input identities. Every aggregate receives an expected version.
The fence binding, idempotency key, tenant, assessment, scope, and timestamp are
preserved in the transaction batch. A reconstructed plan is rejected unless
its batch is exactly the batch derived from its request.

The custody entry content address includes the prior custody content address.
This makes append linkage explicit and tamper evident. It does not by itself
prove that an external store enforces immutability.

## Injected persistence boundary

`ArtifactPersistenceAdapter` defines one method, `commit_artifact`. The method
receives the complete plan and must return an `ArtifactCommitObservation`.
SUNDERKEY does not provide a database implementation in this increment.

At use, the recorder validates and owns its original canonical plan and keeps
its expectations private. The port receives a separately detached plan. Its
returned observation must match the original, not a plan changed by a callback.
See [artifact input integrity](artifact-recording-input-integrity.md) for native
and metadata cost bounds. A rejected observation does not undo a port commit.

An observation is accepted only when it matches the plan across:

- batch identity and batch content address
- tenant, assessment, scope, and idempotency identity
- artifact reference and stored content address
- expected and observed artifact and custody versions
- fence resource, token, and epoch
- custody reference, prior custody link, and new custody entry content address
- optional outbox event identity

Observed aggregate versions must equal their expected versions plus one for
both a new commit and an idempotent replay. A replay is represented explicitly
and produces an `observed_replay` receipt. Reusing the same plan and the same
observation produces the same receipt.

## Nonqualifying receipts

`ArtifactRecordingReceipt` binds the plan, transaction batch, adapter, and
commit observation identities. The receipt distinguishes an observed commit
from an observed replay. It always has `qualification_effect` set to `none`.

The receipt says only that the injected adapter returned a fully matching
observation. Production durability still requires a deployed backend,
transaction and recovery tests, retention enforcement, restore exercises,
custody controls, replication evidence, monitoring, and independent review.

## Validation

Plans, observations, and receipts use canonical JSON, exact field parsing,
content-derived identifiers, content digests, strict round trips, and tamper
rejection. The Draft 2020-12 schema is located at
`registry/schemas/durable-artifact-recorder-v1.schema.json`.
