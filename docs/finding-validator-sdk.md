# Finding validator SDK

The finding validator SDK turns already captured evidence into deterministic validation results. It is infrastructure independent and offline. A validator receives bytes or typed `EvidenceRecord` values. It does not send requests, control a browser, start a process, generate a payload, use a credential, decide target authority, qualify a component, route work, or deploy anything.

The implementation is in `src/sunderkey/finding_validators.py`. The result contract is JSON Schema Draft 2020-12 in `registry/schemas/finding-validation-result-v1.schema.json`.

## Security boundary

Every evidence record has a raw content digest and a record digest. The record digest binds the evidence ID, content digest, media type, role, status, hashed header values, and typed attributes. A caller may provide the expected record digest and the SDK rejects a mismatch before validation. Requests can also bind the complete sorted record digest set and a separate restoration digest set. Evidence bodies remain in memory and are never copied into results.

The default hard ceilings are 64 records, 1 MiB per record, 4 MiB total, 128 headers per record, and 32 caller identifiers. Callers may reduce these limits but cannot raise them. Header metadata rejects control characters. Option objects have depth and item limits.

Results contain only reason codes, counts, safe categories, and evidence content addresses. Authorization headers, cookie values, response bodies, marker text, and canary identifiers are not emitted. Secret-like output from a custom validator is rejected. A canary ID is an inert comparison value only. It is not a credential, secret, authority reference, routing input, or permission grant.

All effect fields in a result are fixed to `none`:

- authority
- credentials
- deployment
- execution
- network
- qualification
- routing

## Result states

The five result states are deliberately separate:

- `verified`: the validator-specific independent corroboration rule passed.
- `negative`: typed evidence supports the absence of the tested condition.
- `hypothesis`: one or more signals exist but required corroboration did not pass.
- `inconclusive`: the evidence can be compared but is ambiguous or incomplete.
- `abstained`: the evidence does not meet the validator's typed preconditions.

Confidence is a number from 0 through 1. It is not authority or qualification. Each result includes stable reason codes, observations, false-positive checks, required and observed corroboration signals, and exact evidence hashes.

A verified result always needs at least two declared signal types. Each built-in validator has a stricter type-specific rule where appropriate. A single signal cannot verify a high or critical impact finding. Restoration evidence is separate from primary evidence. If `restoration_required` is true, a result cannot remain verified unless content-addressed restoration evidence has `restoration_status` set to `verified` and any requested object binding matches.

## Built-in validators

The authorization differential rule requires complete explicit principal and
Boolean access labels on every compared response, one object/action binding,
and a representation-matching pair with distinct principals. Contradictory
expected access for one principal is ambiguous and causes abstention. Repeated
status observations alone are not contradictory access expectations. These
checks operate on asserted metadata; they do not authenticate identities,
establish target authority, or independently prove live exploitability.

The registry contains these exact versions:

| Validator ID | Version | Verified corroboration |
| --- | --- | --- |
| `validator.web.authorization-differential` | `1.0.1` | Unauthorized success, authorized control, and matching nonempty representation for distinct principals on the same object and action |
| `validator.web.input-reflection-context` | `1.0.0` | Caller-provided inert marker bound to request evidence, reflected in an active response context, and absent from control evidence |
| `validator.api.error-oracle-differential` | `1.0.0` | Bound baseline, response class change, body change, and a diagnostic family absent from the baseline |
| `validator.web.security-header-cookie-policy` | `1.0.0` | A successful response plus both missing security headers and insecure cookie attributes |
| `validator.web.redirect-boundary` | `1.0.0` | Redirect status, an unambiguous cross-origin or scheme downgrade boundary, and destination exclusion from the caller allowlist |
| `validator.web.canary-observation` | `1.0.0` | Exact opaque canary match in distinct content addresses from at least two caller-labeled sources |

The validators report categories only. They do not produce exploit strings or instructions.

## Typed evidence

`EvidenceRecord.from_bytes` accepts an ID, byte content, media type, role, optional status code, typed headers, and safe attributes. Common attributes are:

- Authorization differential: `principal_id`, `object_id`, `action`, `expected_access`.
- Reflection: request and response `role` values. Control evidence uses the `control` role.
- Error differential: `variant` with `baseline`, `control`, or `probe`, plus a shared `comparison_id`.
- Redirect: `request_url`. The location is read from a typed `Location` header.
- Canary: `source_id` for independent source comparison.
- Restoration: the `restoration` role, `restoration_status`, and optional `restored_object_id`.

Raw `bytes` are accepted for callers that need content addressing only. Validators that need status, header, role, or comparison metadata abstain when raw bytes do not supply it.

## Registry and version binding

`build_default_registry()` builds an immutable registry from the reviewed descriptors. Lookup always requires both validator ID and semantic version. There is no latest-version fallback. A request may bind `registry_sha256`; mismatches fail before assessment.

Each result binds:

- canonical validation input hash, including opaque identifier hashes and an options hash
- scope ID
- technique ID
- finding impact
- validator ID and exact version
- validator descriptor hash
- registry hash
- primary evidence hashes
- restoration evidence hashes
- observations and false-positive checks

The result ID and result SHA-256 cover the full canonical result body. `FindingValidationResult.from_dict` detects tampering. `FindingValidatorRegistry.verify_result` additionally detects registry or descriptor drift.

Neither result parser nor registry binding verification re-assesses response
evidence. Intact content addresses alone are not current-rule corroboration,
source authentication, target authorization, or approval for positive use.

### Authorization rule transition

Authorization version `1.0.1` identifies the hardened explicit-principal,
complete-access-label, and pair-specific corroboration checks. The descriptor,
registry, validation input, and result identities change together. The previous
`1.0.0` authorization rule is not registered, and lookup does not silently
upgrade it. The other five validators retain their own `1.0.0` descriptors,
but results produced through the default registry also bind its new digest.

Keep prior artifacts unchanged for archival inspection. An old result may
retain a valid content address while failing the current registry binding.
Do not rewrite its version or digest to make it appear current. Re-assess the
original evidence under the exact new registry to obtain a new result.
The [synthetic API source verifier](offline-api-assessment.md) replays the
current rule; it does not dispatch to historical implementations. The
[planning archive inspector](offline-api-planning-bundle.md) remains explicitly
non-authorizing and does not re-assess historical case evidence.

## Minimal use

```python
from sunderkey.finding_validators import EvidenceRecord, validate_finding

first = EvidenceRecord.from_bytes(
    "canary-observation-a",
    b"captured response containing canary-42",
    status_code=200,
    attributes={"source_id": "sensor.a"},
)
second = EvidenceRecord.from_bytes(
    "canary-observation-b",
    b"independent captured response containing canary-42",
    status_code=200,
    attributes={"source_id": "sensor.b"},
)

result = validate_finding(
    scope_id="scope.assessment.17",
    technique_id="CUSTOM.CANARY.1",
    validator_id="validator.web.canary-observation",
    validator_version="1.0.0",
    evidence=(first, second),
    canary_ids=("canary-42",),
    expected_evidence_hashes=(first.evidence_sha256, second.evidence_sha256),
)
```

The same canonical inputs and exact registry produce the same `document_json`, result ID, and result hash.
