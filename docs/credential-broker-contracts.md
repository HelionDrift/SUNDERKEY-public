# Credential Broker Contracts

The credential broker contract layer defines how SUNDERKEY may refer to test
credentials without storing or resolving credential material. It is an offline
policy and evidence boundary. It is not a vault client, secret resolver,
authentication service, session creator, network adapter, or execution path.

## Security boundary

Every field that identifies an organization, assessment, task, principal,
target, technique, purpose, provider, adapter, scope, session, issuance, role,
reason, credential, or obligation uses a typed reference namespace. Raw user
names, passwords, tokens, private keys, cookies, one-time codes, and magic-link
contents have no field in the model. Provider adapters have exact numeric
versions. Moving aliases are rejected.

Canonical JSON and SHA-256 content addresses make every descriptor, request,
approval, identity set, lease, usage receipt, and lifecycle obligation
deterministic and tamper evident. Serialized records can be checked without
trusting their declared identifier or digest.

## Contract flow

1. A credential descriptor names an opaque credential reference and constrains
   its tenant, assessment, subject principal, provider adapter, targets,
   techniques, purposes, scopes, lease modes, TTL, use count, and lifecycle
   obligations.
2. An access request binds one requester, subject principal, task, target,
   technique, purpose, action tier, scope set, mode, TTL, and use ceiling to one
   descriptor.
3. An independent approval binds exactly one request. The requester and subject
   principal cannot approve the lease. Higher action tiers require distinct
   approvers in distinct control, assurance, and risk-owner roles.
4. Lease issuance rechecks every binding and every ceiling. The explicitly
   supplied time must be at or after descriptor creation, request creation,
   and approval time, and strictly before each source record's expiry.
   Silence, missing evidence, an inactive or expired record, an unknown mode,
   or a mismatched value denies issuance.
5. Usage receipts consume numbered uses and repeat the tenant, assessment,
   task, principal, target, technique, purpose, and session bindings. Replayed,
   expired, exhausted, revoked, or substituted use is rejected.
6. Revocation and rotation obligations bind a responsible role, due time,
   reason reference, trigger digest, and optional completion proof. They record
   duties but do not perform provider actions.

## Least privilege and separation

Requested scopes must be a subset of descriptor scopes. Approved scopes must
be a subset of requested scopes. Approved TTL and use count must not exceed the
request, and the request must not exceed the descriptor. A one-time lease has
exactly one use and no session reference. A session-bound lease requires a
preexisting session reference. The contract never creates that session.

Multi-principal tests use an explicit identity set with at least two distinct
principal references and two distinct credential descriptor digests. This
prevents accidental reuse of one identity across authorization-boundary tests.

Approval bindings are single use. Callers provide consumed approval digests to
the pure issuance function, which rejects replay. A renewal request binds the
exact prior lease digest and requires a new request-specific approval. The old
approval cannot authorize the renewed lease.

These source activation checks apply to access validation and lease issuance,
not historical content-address inspection. Lower-bound equality is allowed;
expiry equality is denied. A valid future-dated source can still be inspected
without granting current admission. Source timestamps are declared metadata,
not proof of an authenticated clock, approval, credential delivery, or target
permission.

## Deliberate non-capabilities

This increment performs no approval, authentication, credential lookup,
credential delivery, decryption, login, session creation, provider call,
network access, shell command, or assessment action. It grants no authority and
does not make an untrusted reference safe. A future infrastructure adapter must
verify these contracts again at its own trust boundary and must preserve the
same fail-closed rules.

## Schema

`registry/schemas/credential-broker-contract-v1.schema.json` is a strict JSON
Schema union for every record type. Each object rejects unknown properties and
uses closed vocabularies, bounded arrays, typed references, canonical UTC
timestamps, exact versions, bounded TTL and use counts, and fixed identifier
and digest formats.
