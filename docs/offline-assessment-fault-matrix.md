# Offline assessment fault matrix

The matrix runs 72 named tests from the repository as one bounded local
conformance check. Categories cover cancellation and health pause, source
expiry, target-health denial, worker fencing, indeterminate provider result,
budget exhaustion, cross-batch receipt replay, recovery, tenant isolation,
identity path replay, identity policy attachment, identity hop-plan rebinding,
identity membership and record freshness,
concurrent idempotent import, reviewer and report rebinding, archive fault
isolation, source signature rebinding, synthetic benchmark reconciliation,
attested planning rebinding, private benchmark opening rebinding, API
security-declaration rebinding, API access-expectation rebinding, API
retest expectation drift, API retest assertion rebinding,
API access-policy local signature rebinding,
API access-policy JSON type substitution,
API policy and source-attestation rebinding,
API security-scheme source rebinding, OAuth flow definition validation,
benchmark adjudication receipt rebinding,
benchmark operational receipt rebinding,
cross-receipt benchmark event replay,
benchmark dual-signature rebinding,
benchmark receipt-family completeness,
private benchmark truth and decision rebinding,
benchmark preregistration signature rebinding,
benchmark preregistration JSON type substitution,
benchmark cross-stage packet rebinding,
comparison live-readiness claim rebinding,
MCP schema invalid keyword or depth rejection,
MCP header invalid-name or duplicate rejection,
MCP header unreachable or nonprimitive annotation rejection,
MCP header value injection and encoding rejection,
MCP header-to-body parity rehearsal,
offline documentation count drift, cross-batch telemetry gaps or replay,
telemetry pipeline cursor or replay faults, remediation source/window replay,
remediation exception and idempotency replay, exact remediation case types,
open-descriptor source identity, bounded CLI output bytes, missing remediation
evidence, exact typed offline evidence, constructor effect-map ownership,
ambiguous authorization pairs and exact validator versions, API observation
source digests, role/status association swaps, event stop-switch replay,
stale evidence bindings, MCP literal schema scope, current-source coverage
inflation, native API scalar and freshness capture, and the three combined
API archive-to-event/history, foreign-scope, and stop/retry/duplicate paths.

The plan records each exact test ID and its file digest. A missing, moved,
duplicated, skipped, or failed test cannot count as a pass. The run output
records per-category status and a content digest. It performs no target
interaction and has no qualification effect. This is a representative registry,
not the full test suite. Test-file hashes identify the selected file bytes;
they are not a transitive digest of imported helpers, fixtures, or sources.

From the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m sunderkey.offline_assessment_fault_matrix --check-plan
python -m sunderkey.offline_assessment_fault_matrix --run
python scripts/check_offline_documentation.py
```

The last command is also a fast CI preflight. It compares current prose counts
for this matrix, the synthetic benchmark corpus, and the continuation streams
against their source definitions. It does not validate the underlying claims.

These checks use synthetic fixtures and injected backends. A passing matrix
does not establish that a deployed target, cloud account, provider, key store,
or reviewer behaves the same way. It is a repeatable pre-infrastructure
regression gate, not live assessment evidence.
