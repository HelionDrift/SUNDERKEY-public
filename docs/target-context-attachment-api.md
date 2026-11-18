# Target context attachment API

The target context attachment API adds one bounded, content-addressed operation
to the local service boundary. It accepts either caller-supplied bytes or an
already built `TargetContextBundle`. It does not accept a URL, directory, or
filesystem path.

The operation is `attach_target_context`. The stored resource kind is
`target_context`, and the resource identifier is always the bundle identifier.
Callers cannot choose a different resource identifier.

## Byte attachment

`TargetContextSourceAttachment` holds one caller-owned byte sequence and optional
media, kind, and expected hash declarations. `TargetContextAttachmentRequest`
requires at least one source, explicit provenance, mission and authority
bindings, an access context, an idempotency key, and the exact authorization
decision and authorization audit references expected from the local service.

`TargetContextAttachmentApi.attach()` sends the bytes only to the existing
offline target-context parser. The parser enforces the media allowlist, portable
path policy, source and archive size limits, file-count limits, decompression
ratio limits, nesting limits, secret redaction, and hostile-content quarantine.
The API then supplies only the resulting bundle to the injected
`LocalApiService`. Raw source bytes are not placed in the resource, audit entry,
integration event, or receipt.

The attachment request can be serialized as canonical JSON. Byte content uses
unpadded base64url plus an explicit size and SHA-256 digest. Deserialization
checks all three values before the operation can proceed.

## Existing bundle attachment

A caller may provide a `TargetContextBundle` instead of bytes. The API rebuilds
the bundle from its document and verifies its content identity, mission binding,
authority binding, provenance, limits, safe structural facts, quarantine state,
and no-effect declaration. Bundle mode cannot replace provenance or limits.

Direct `LocalApiService` callers may use `Operation.ATTACH_TARGET_CONTEXT` with
`ResourceKind.TARGET_CONTEXT`. The payload must contain exactly one `bundle`
field, that value must pass `TargetContextBundle.from_dict()`, and the resource
identifier must equal the bundle identifier.

## Idempotency and receipts

The API delegates authorization, mutation admission, atomic persistence, audit,
integration event creation, and idempotency to the existing injected local
service ports. An exact retry returns a `replayed` receipt and no second commit.
Reusing an idempotency key with changed content fails closed.

Before publishing a receipt, the facade verifies that the service response is
terminal and binds the exact request ID and request digest. It also requires the
resource tenant, context, kind, identifier, payload, version, and content digest
to match the request and bundle. The authorization decision and authorization
audit references must exactly equal the values content-addressed in the
attachment request. The mutation audit reference must use the expected
namespace and be present on the resource, and the integration event must bind
that same audit reference and the exact resource identity, digest, tenant,
context, version, event type, and request timestamp. A rebound or incomplete
response cannot produce a receipt.

`TargetContextAttachmentReceipt` binds:

- the attachment request hash and delegated service request hash;
- the idempotency-key hash;
- the bundle ID, bundle digest, status, mission, authority reference, and source
  provenance;
- input, artifact, redaction, and quarantine counts;
- the resource version and concurrency token;
- authorization, mutation audit, and integration event references; and
- the completion or replay status.

The receipt ID and digest are derived from canonical JSON under a dedicated
domain. `from_dict()` recomputes the identity and rejects field, count, digest,
or no-effect changes. The schema is
`registry/schemas/target-context-attachment-api-v1.schema.json`.

## Boundary and non-claims

The facade opens no socket, performs no fetch, resolves no external reference,
reads no caller path, and creates no execution environment. The receipt fixes
authority, execution, filesystem, network, qualification, and runtime effects to
`none`. Repository write behavior remains injected. An `authority_ref` is only a
bundle binding and does not create or extend authority. A successful attachment
does not qualify an expert, approve a target, authorize an action, or claim that
any runtime exists.
