# Assessment transport contracts

`sunderkey.assessment_transport_contracts` defines the typed boundary between an
authorized assessment task and an infrastructure-specific transport. The module
ships protocol definitions plus deterministic scripted mocks. It does not ship a
network backend, browser driver, process launcher, or credential resolver.

## Authority binding

Every request intent carries an `AssessmentBinding`. The binding fixes all of the
following before an adapter can act:

- verified scope ID and signed scope content hash;
- coverage task ID and technique ID;
- authority references and evidence hashes;
- impact tier, deterministic decision time, and mandatory stop conditions;
- request, byte, MIME, redirect, and step budgets;
- adapter ID and version.

An adapter method accepts a `VerifiedAssessmentScope`, not a mapping or a signed
but unverified scope. The adapter checks the scope identity against the binding
and obtains a fresh `ScopeDecision` through `evaluate_request`. A denied decision
fails closed. The decision is recorded in the transcript for every accepted,
cancelled, stopped, paused, or completed step.

The adapter identity in the binding must match every preflight and continuous
health observation. A degraded or unavailable continuous observation creates a
`health_paused` step without consuming a scripted result. Caller cancellation and
stop signals create `cancelled` and `stopped` steps. These states are explicit and
cannot be confused with a completed observation.

## Separate adapter interfaces

The module publishes three runtime-checkable protocols:

1. `HttpExchangeAdapter` accepts `HttpRequestIntent` and returns a bounded HTTP
   observation.
2. `BrowserActionAdapter` accepts `BrowserActionIntent` and returns metadata,
   cookie attributes, and evidence references.
3. `TargetSessionAdapter` accepts `TargetSessionIntent` and returns an isolated
   session identity bound to one principal label.

Each interface includes `preflight`, `observe_health`, and `transcript` methods.
The supplied implementations are `DeterministicHttpTransport`,
`DeterministicBrowserTransport`, and
`DeterministicTargetSessionTransport`. They replay exact intent hashes in order.
They perform no external I/O. A new mock instance with the same binding, health
script, request, and result script produces the same step and transcript hashes.

## HTTP controls

HTTP requests use a closed method enumeration. Request bodies are represented
only by a byte count and SHA-256 digest. Response bodies are represented the same
way. Per-step and cumulative byte ceilings are mandatory. MIME types must appear
in the explicit `MimeLimit` list, and each type has its own byte ceiling.

Request and response headers are controlled by separate allowlists. Credential
headers, cookie headers, and common token headers are forbidden. Selected safe
response headers can be retained only as a redaction marker with a null value.
Cookie observations contain name, domain, path, Secure, HttpOnly, and SameSite
metadata, never the cookie value.

Redirect observations count against an explicit limit. Download results are
always rejected. Redirect destinations still remain hash-bound evidence and do
not cause the scripted mock to follow a connection.

## Browser controls

The browser action vocabulary is closed:

- `navigate`
- `click_selector`
- `fill_reference`
- `submit`
- `wait_condition`
- `read_metadata`
- `screenshot_reference`

There is no script evaluation action and no arbitrary file upload action.
Selectors and conditions reject script URLs, script tags, evaluation syntax,
file selectors, and file URLs. `fill_reference` accepts an opaque `credref:`
reference instead of a value. `screenshot_reference` accepts an `evidref:` or
SHA-256 reference instead of a file path or file content.

Every browser action requires a `SessionBinding` with both a session ID and a
principal label. Reusing a session ID under another principal fails closed. This
preserves the principal separation required for IDOR tests.

## Target authentication controls

Target authentication supports exactly these declared modes:

- `basic`
- `bearer`
- `form_login`
- `totp_reference`
- `magic_link_reference`
- `social_login_reference`
- `multi_principal_test_accounts`

All modes accept only `PrincipalCredentialReference` values. A reference must use
the `credref:` namespace. Raw usernames, passwords, tokens, TOTP values, link
contents, and social credentials have no field in the contract.

Single-principal modes require exactly one labeled reference. The multi-principal
mode requires at least two unique labels. A selected principal must have a
matching declared reference. Every request must ask for isolation, and the result
must return the exact requested session ID and principal. Session substitution,
principal substitution, and cross-principal session reuse are rejected.

## Transcript integrity

Each successful or terminal control step includes:

- a contiguous sequence number;
- the complete typed intent and its content hash;
- the allow decision and deterministic health observation;
- a typed observation or an explicit terminal stop reason;
- the preceding step hash;
- fixed no-effect fields;
- its own content hash.

`build_transport_transcript` verifies the chain and derives the transcript hash
and `ATT-` ID from canonical ASCII JSON. `TransportTranscript.from_dict` repeats
all structural and cryptographic checks. It rejects changed results, reordered
steps, changed effects, mismatched intent hashes, result substitution, and extra
fields. Runtime verification is required even when the published JSON Schema has
already accepted a document.

The fixed no-effect fields state that the transcript and offline mocks do not
grant authority, control a real browser, expose credential values, deploy,
execute, access a network, qualify, route, or invoke a shell. A scripted result
that changes any no-effect field is rejected before a completed step is recorded.

## Fail-closed rejection summary

Adapters and constructors reject:

- unverified, mismatched, inactive, or out-of-scope authority;
- unknown methods, actions, authentication modes, or MIME types;
- exhausted scope, step, byte, redirect, concurrency, or rate budgets;
- raw credentials, secret fields, secret headers, and non-reference fill data;
- response headers outside the allowlist and cookie value fields;
- unsafe browser script or file access syntax;
- downloads and responses over per-step, cumulative, or MIME ceilings;
- missing principal labels, disabled isolation, and cross-principal reuse;
- unhealthy continuous observations, with a recorded pause;
- scripted result substitution and any effect escalation;
- noncontiguous sequences or any transcript hash-chain tampering.

`registry/schemas/assessment-transport-transcript-v1.schema.json` is a closed
Draft 2020-12 schema for the published transcript representation. JSON Schema
does not recompute hashes or run scope decisions, so consumers must also call
`TransportTranscript.from_dict`.
