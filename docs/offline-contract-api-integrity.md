# Offline contract and API result integrity

This increment hardens existing contract parsing, retained local metadata and
API result verification. It uses disposable synthetic stores and in-process
ports only. It performs no network, provider, cloud or target operation and
changes no qualification, activation, action tier, D014 selection, MissionStore
schema or authorization source.

## Exact addressed documents

[Action-admission](action-admission-contracts.md) requests and decisions, and
the six top-level [authenticated-target contracts](authenticated-target-contracts.md),
must reproduce the complete canonical JSON document on parsing. Python mapping
equality can equate different native JSON types; it cannot prove byte-level
agreement with an addressed document.

The regression controls retain eight original identifiers and hashes. They
show that substituting `true` or `1.0` for schema version `1` changes addressed
bytes even when Python equality succeeds. Public parsers reject those documents
instead of normalizing them under the original identity. Valid round trips,
object order, strict integer and Boolean fields, no-effects declarations and
existing local admission outcomes remain unchanged.

## Durable admission reconstruction

The genuine authenticated admission
fixture supplies synthetic signed authority and an existing local receipt.
Tests change only the retained request JSON in a disposable store while keeping
its original identity, receipt and custody hashes. The original immutable
SQLite guard is restored before every verifier.

Historical reconstruction, mission verification, store-wide verification and
live current verification now reject the changed request. The tests restore
the exact original row and guard and compare the whole logical store to catch
incidental writes. Altered decision JSON retains its separate existing raw
custody-hash rejection; that is not credited as a newly repaired path.

Normal current verification still performs its existing health-observation,
transition and use writes. It is not relabeled as read-only. Historical
integrity and live-currentness remain distinct, and no synthetic receipt is
promoted to operational qualification or new action authority.

## Atomic API result joins

The [local service](local-api-service.md) verifies the retained resource, audit
entry and integration event as one result. Their exact tenant, context,
resource kind and ID, version, audit head, request hash, concurrency token,
operation and timestamps must agree. Event identity and resource hash are
reproduced from the existing event construction, and the audit identity from
its original retained decision references and prior token.

The result must also match the original request's principal, expected prior
token, payload and update time. A coherently rehashed wrong payload is not a
result for that request. A newly committed result must retain the exact
resource, audit entry and event constructed in its commit command. An actual
update command preserves the prior record's creation time.

Idempotent replay retains its original resource snapshot and historical
authorization and admission references, even after the current record or fresh
decisions change. Replay still runs fresh authorization and admission through
the existing service path; historical references are not compared to fresh
references as though they were the same decision. No missing prior snapshot is
invented to validate retained metadata.

The [SQLite adapter](local-api-runtime-adapter.md) checks the stored JSON hash,
rejects duplicate or discarded fields and native-type normalization, reconstructs
the exact document and verifies its self-contained joins before returning it.
Tests exercise its actual hash-checked read and public in-process ASGI path,
plus fresh commits, reopen, update and original-snapshot replay controls.

These checks establish local consistency, not external authenticity. They do
not authenticate supplied repository metadata independently, qualify an
injected authorizer or repository, undo an already applied external write,
deliver an event, or supply a live service deployment.
