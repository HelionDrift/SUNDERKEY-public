# Cryptography and PKI Specialist Contracts

`sunderkey.crypto_pki_specialist_contracts` defines a repository-only
assessment boundary for eight specialist families:

- cryptographic protocols
- PKI trust and path policy
- TLS and mTLS configuration
- certificate lifecycle controls
- secrets and key management
- signing and verification
- token and identity protocols
- cryptographic misuse analysis

The module provides deterministic declarations, evidence provenance records,
assessment requests, findings, adapter observations, and receipts. It does not
contain a network client, scanner, command runner, key generator, keystore
client, secret resolver, credential handler, TLS client, certificate parser,
token parser, signing implementation, or target implementation.

## Assessment coverage

The declaration catalog separates focused checks across the eight families.
It covers protocol version and cipher policy, trust paths, revocation policy,
TLS configuration, mTLS identity binding, certificate issuance and renewal,
secret inventory hygiene, key custody and rotation, signature verification,
token validation, identity protocol binding, algorithm and parameter misuse,
nonce and initialization vector policy, and key usage separation.

The contracts identify the assessment surface without embedding attack
payloads, downgrade logic, private key operations, live handshake behavior, or
credential use. A check that is outside the selected specialist family fails
before an adapter can be called.

## Explicit authorization and admission

Every assessment context binds these opaque references and digests:

- tenant and repository assessment context
- approved scope
- explicit authorization
- action-admission decision
- evidence plan
- cryptographic policy
- trust policy
- request budget

Authorization has a bounded validity window. The context must state that the
repository assessment is explicitly authorized and that target interaction is
not authorized. A request must fit entirely inside the authorization window.
At dispatch, the complete context is compared with an independently supplied
expected context and checked again at the evaluation time.

## Evidence provenance

Evidence records carry only opaque references, digests, timestamps, bounded
byte counts, evidence classifications, and an ordered custody chain. Supported
classifications cover synthetic certificate manifests and sanitized summaries
for TLS configuration, handshakes, trust paths, revocation, key lifecycle,
secret inventory, signature policy, token claims schemas, identity protocols,
and source analysis findings.

Every evidence record must be sanitized. It must assert that it contains no
private key, secret value, credential, live target capture, or executable
material. Raw certificates, handshakes, keys, secrets, tokens, credentials,
protocol frames, and source excerpts are not fields in the wire contract.
Canonical serialization also rejects common secret material patterns.

## Fail-closed adapter boundary

The dispatcher validates declaration binding, full context binding, active
authorization, request freshness, replay state, idempotency, evidence
provenance, estimates, and budgets before invoking one caller-supplied adapter.
There is no built-in adapter.

An accepted observation must prove that the adapter performed no network call,
scanner execution, command execution, key generation, key access, secret
access, credential handling, or target interaction. The observation must bind
the exact request, context, and evidence set. Reported counts must remain
inside both the request estimates and context budget.

## Findings and remediation references

Findings contain a category, severity, policy rule reference, bounded evidence
references, a remediation reference, and a confidence basis. They contain no
remediation commands, exploit instructions, key material, token material, or
raw evidence. Every finding must cite evidence in the request.

The outcome rules are deterministic:

- `pass` cannot include findings
- `control_gap` requires at least one finding
- denied or failed adapter results must be `inconclusive` without findings

This structure supports policy and misuse analysis while preserving a strict
separation between observation, remediation planning, and any future action.

## Integrity and qualification

Canonical JSON uses sorted keys, printable ASCII, bounded types, and SHA-256
content identities. Declarations, evidence records, requests, findings, and
receipts are deterministic. The parser reconstructs each supported top-level
wire record and rejects altered identities, unexpected content, malformed
structures, and unsupported record kinds.

All top-level records set `qualification_effect` to `none`. This increment is
repository-only and nonqualified. Production use still requires separately
approved evidence collectors and assessment adapters, durable replay storage,
trusted authorization and admission services, key and secret custody controls,
transport enforcement, evidence custody, operator controls, and independent
qualification.
