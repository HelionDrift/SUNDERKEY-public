# Defender Telemetry Adapter Contracts

The Phase 167 telemetry adapter layer provides repository-only contracts for the defender telemetry portions of D8.1 through D8.4. It gives network, identity, cloud, application and API, endpoint, and SIEM sources one normalized import boundary. It does not claim a live integration, production readiness, or qualification.

## Boundary

`sunderkey.defender_telemetry_adapters` is deterministic and import-only. It does not contain a source client, network transport, credential resolver, collection loop, persistence implementation, or write path into a telemetry system. The caller supplies references to already retained and redacted telemetry plus a pure normalizer.

Every completed ingest batch declares these effects as `none`:

- authorization
- collection
- network activity
- persistence
- qualification
- source writes
- target actions

The normalizer receives only a validated source binding and a redacted envelope reference. Raw event bytes and credentials are outside this contract.

## Exact source context

A telemetry source binding fixes the tenant, engagement, signed scope digest, source, telemetry domain, adapter and version, source schema digest, normalization mapping digest, custody policy digest, processing region, freshness policy, and active interval. The six supported domains are:

- network
- identity
- cloud
- application and API
- endpoint
- SIEM

Every envelope repeats the content-addressed binding identity and its tenant, engagement, scope, source, and domain context. A mismatch fails before the normalizer is called. This prevents an event imported for one tenant, assessment, source, or scope from being relabeled under another context.

## Custody and minimization

An envelope contains references and digests, not raw telemetry. It requires:

- a durable verified custody state;
- an artifact reference and custody digest;
- a raw event digest;
- explicit redaction;
- the source event reference and sequence;
- event and receipt timestamps.

Opaque reference validation rejects secret-like material. Normalized attributes contain only a canonical field name and an opaque value reference. This keeps the common event shape useful for correlation without turning the contract into a store for source payloads, credentials, tokens, or cookies.

## Freshness and replay protection

Each source binding defines maximum event age, maximum import delay, allowed future clock skew, and replay retention. Import validation rejects:

- inactive or expired source bindings;
- events older than the permitted event age;
- receipts held longer than the permitted import delay;
- event or receipt timestamps beyond the allowed clock skew;
- duplicate event references, payload digests, or source sequences in a batch;
- active replay markers for a previously accepted event reference or payload digest;
- replay state from a different tenant, engagement, scope, or binding.

Expired replay markers no longer block an otherwise valid import. New markers are returned as part of the immutable batch so an external persistence implementation can commit them atomically with the normalized events. This module does not persist them.

## Normalized event model

The injected normalizer returns a projection containing the source event reference, raw event digest, exact mapping digest, event category, operation code, outcome, severity, actor, subject, resource, and optional opaque attributes. The adapter rejects a projection if it changes the source event, payload digest, or mapping digest.

The resulting normalized event preserves the full source context and envelope content addresses. Supported categories cover authentication, authorization, configuration, data access, execution, network flow, resource change, and security alerts. Outcomes and severities use bounded canonical enumerations so downstream correlation does not depend on vendor-specific labels.

## Infrastructure still required

The contracts do not make telemetry available. A deployment still needs separately reviewed and authorized infrastructure for:

- source-specific clients and credentials;
- collection scheduling and checkpoints;
- tenant-isolated durable storage;
- atomic replay marker persistence;
- regional processing enforcement;
- source schema and mapping governance;
- operational monitoring and recovery;
- live conformance and independent qualification.

An accepted batch proves only that caller-supplied references passed this deterministic boundary. It does not prove that a source was reached, that telemetry is complete, or that a defensive control detected an action.

## Verification

`registry/schemas/defender-telemetry-adapter-contract-v1.schema.json` validates source bindings, envelope references, normalized events, and ingest batches. Focused tests cover all six source domains, deterministic normalization, content-addressed round trips, freshness, clock skew, custody, redaction, tenant and scope isolation, replay handling, projection binding, tamper rejection, immutability, schema validation, and source-free marker scans.
