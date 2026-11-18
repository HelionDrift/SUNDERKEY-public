# Signed assessment scope v1

The signed scope compiler converts an already-ingested assessment authorization into a canonical, content-addressed, Ed25519-signed document. It is an offline policy boundary. Compilation, verification, overlap checks, and request checks do not perform network calls or produce qualification, routing, deployment, execution, or authority effects.

The implementation is in `sunderkey.signed_scope_compiler`. The portable document schema is `registry/schemas/signed-assessment-scope-v1.schema.json`.

## Trust model

The signing private key is a separate argument to `compile_signed_scope`. It is never placed in the source specification, returned object, canonical JSON, content hash, or verification result. The signed document also contains no public key.

Verification requires all of the following out of band:

- the expected issuer identifier
- the expected key identifier
- the exact Ed25519 public key
- the verification time and, when used, a sequence-number floor

The signature covers the issuer, key identifier, nonce, sequence number, all constraints, the fixed no-effect declarations, the content address, and the signature algorithm under a versioned signing domain. Replacing any of those values invalidates verification. Supplying a different public key does not change the signed identity pins and cannot substitute authority.

Possession of a valid signed scope is not a grant of routing, deployment, qualification, or execution. A downstream adapter must separately be authorized to act, must maintain budget counters, and must call `evaluate_request` or `request_is_in_scope` before each proposed request.

## Compiler input

The compiler accepts a Python mapping or a strict UTF-8 JSON object. JSON duplicate keys, floating-point values, non-finite numbers, unknown fields, non-ASCII security identifiers, and probable secret fields or values are rejected.

The source object has exactly these fields:

```json
{
  "schema_version": 1,
  "issuer": "assessment-authority.example",
  "key_id": "scope-signing-key.2026-09",
  "nonce": "Tkd4ZWlDN1p3RkJNUQ",
  "sequence_number": 42,
  "issued_at": "2026-09-20T03:00:00Z",
  "expires_at": "2026-09-20T05:00:00Z",
  "assessment_window": {
    "starts_at": "2026-09-20T03:00:00Z",
    "ends_at": "2026-09-20T04:30:00Z"
  },
  "targets": {
    "https_origins": ["https://api.example.test"],
    "exact_hosts": ["api.example.test", "192.0.2.10", "2001:db8::10"],
    "wildcard_subdomains": ["*.staging.example.test"],
    "cidrs": ["192.0.2.0/28", "2001:db8::/124"],
    "ports": [443, 8443],
    "http_methods": ["GET", "POST"],
    "path_prefixes": ["/api/v1", "/health"]
  },
  "exclusions": [
    {
      "exclusion_id": "exclude.admin-writes",
      "https_origins": [],
      "exact_hosts": [],
      "wildcard_subdomains": [],
      "cidrs": [],
      "ports": [],
      "http_methods": ["POST"],
      "path_prefixes": ["/api/v1/admin"]
    }
  ],
  "protected_endpoints": ["https://api.example.test/health/ready"],
  "budgets": {
    "max_requests": 1000,
    "max_concurrency": 8,
    "max_requests_per_minute": 120
  },
  "impact_tier_ceiling": "R2",
  "allowed_technique_ids": ["AT3-GB-D06-S09-01"],
  "data_handling": {
    "classification": "confidential",
    "collection": "minimized_content",
    "storage": "ephemeral_encrypted",
    "retention_days": 7,
    "redaction_required": true
  },
  "emergency_stop_contact_id": "soc.oncall.primary"
}
```

Arrays are normalized into ascending order. HTTPS origins, hosts, IP addresses, networks, methods, and paths are normalized before hashing. A duplicate created by normalization is rejected rather than silently discarded.

## Target semantics

Every request must use HTTPS. Userinfo, queries, fragments, percent encoding, backslashes, whitespace, empty ports, traversal segments, repeated path separators, and Unicode host or path text are rejected as ambiguous.

An allowed network target is the union of:

- exact normalized HTTPS origins
- exact DNS hosts or IP literals on an allowed port
- one-label wildcard subdomains on an allowed port
- IP addresses inside an allowed canonical CIDR on an allowed port

A wildcard is limited to one leftmost label. For example, `*.example.test` matches `a.example.test`; it does not match `example.test`, `a.b.example.test`, or `evil-example.test`. Bare top-level wildcards and recognized multipart public-suffix wildcards are rejected. V1 intentionally has no override for `0.0.0.0/0` or `::/0`.

Path prefixes use segment boundaries. `/api` contains `/api` and `/api/items`, but not `/apiary`. Methods are normalized to uppercase. A request must also name an allowed technique ID and an impact tier no greater than the ceiling.

An exclusion is a conjunction across its non-empty dimensions. Empty dimensions mean any value. Exclusions always win over target allows. Exclusions that cannot intersect the allow region, and exclusions fully shadowed by another exclusion, are rejected. Protected endpoints are exact normalized origin and path pairs, are always denied, and must be inside the allow region.

## Time and budgets

The ordering is:

`issued_at <= assessment_window.starts_at < assessment_window.ends_at <= expires_at`

V1 lifetime is at most 31 days. Compilation and verification deny future-dated scopes, scopes whose assessment window has not started, expired windows, and expired scopes.

Budgets are bounded as follows:

- `max_requests`: 1 through 1,000,000
- `max_concurrency`: 1 through 256 and no greater than `max_requests`
- `max_requests_per_minute`: 1 through 60,000

`evaluate_request` requires a `ScopeBudgetState` with completed, active, and current-minute counts. Missing, negative, or exhausted counters produce a deny decision. The compiler does not mutate counters.

## Compile and verify

```python
from datetime import UTC, datetime

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sunderkey.signed_scope_compiler import (
    ScopeBudgetState,
    compile_signed_scope,
    evaluate_request,
    verify_signed_scope,
)

private_key = Ed25519PrivateKey.generate()
public_key = private_key.public_key()
at = datetime(2026, 9, 20, 3, 30, tzinfo=UTC)

signed = compile_signed_scope(specification, private_key, now=at)
verified = verify_signed_scope(
    signed,
    public_key,
    expected_issuer="assessment-authority.example",
    expected_key_id="scope-signing-key.2026-09",
    now=at,
    minimum_sequence_number=42,
)

decision = evaluate_request(
    verified,
    url="https://api.example.test/api/v1/items",
    method="GET",
    technique_id="AT3-GB-D06-S09-01",
    impact_tier="R1",
    budget_state=ScopeBudgetState(0, 0, 0),
    at=at,
)
assert decision.allowed
```

Passing a verified `authority_ceiling` to `compile_signed_scope` adds a fail-closed structural containment check. A child cannot expand target hosts, ports, methods, paths, techniques, impact, time, budgets, data handling, or protected resources. The issuer and key ID must stay pinned, sequence numbers cannot move backward, and each parent exclusion that can still intersect the child must remain in the child.

## Overlap and containment

`scopes_overlap(left, right)` tests the signed allow regions for a common active time interval, technique, method, path, host or network, and port. It is useful as a deterministic prefilter. Request evaluation remains the final check because exclusions and protected endpoints have deny precedence.

`scope_contains_scope(container, candidate)` tests whether the candidate stays within a verified authority ceiling. Both operands must be `VerifiedAssessmentScope` values. Unverified mappings and signed but unverified documents are rejected.

All operations are pure local computation over supplied values. The module has no resolver, socket, HTTP client, registry mutation, routing call, deployment call, or executor call.
