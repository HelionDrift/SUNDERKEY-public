# Authorized browser action runtime

Phase 174 adds a repository-only, fail-closed boundary for one admitted browser action. The boundary can invoke an injected browser driver after validating exact authority and control bindings. It does not include a browser implementation, credential resolver, network client, script engine, payload, secret provider, or deployment integration.

## Required bindings

Each action requires all of the following:

1. A cryptographically verified `VerifiedAssessmentScope`.
2. A closed `BrowserActionIntent` from the assessment transport contracts.
3. An `ExecutionRequest` and admitted `AdmissionReceipt` with exact request, binding, scope, session, policy, payload hash, payload size, and first-attempt bindings.
4. An `AuthorizedBrowserPolicy` bound to one isolated session and one principal.
5. Caller-supplied atomic browser budget repository, clock, safety monitor, and
   browser driver.

The runtime performs a fresh signed-scope decision for every action. Only credential-free HTTPS URLs are accepted. The pre-action and post-action origin must both equal the receipt-bound intended origin before the result can be completed, and the driver must attest to the exact session and principal before the result can be accepted. A cross-origin result can be recorded only as a scope-rejected postcondition failure.

## Closed action surface

The action vocabulary is limited to:

* HTTPS navigation
* click by selector
* fill from an opaque `credref:` reference
* form submission
* allowlisted wait conditions
* metadata reading
* screenshot capture to an opaque `evidref:` or SHA-256 reference

Selectors and conditions are printable ASCII, length bounded, and screened for script, file input, download, clipboard, extension, pop-up, and related escape syntax. Wait conditions use only `present:`, `absent:`, or `url_equals:` forms.

The injected driver receives opaque references only. SUNDERKEY does not resolve or record credential values. Driver results contain metadata and references, not page bodies or secrets.

## Continuous controls

The runtime enforces all of these controls before the driver call:

* admitted execution state and exact content hashes
* signed scope, path, technique, impact, and request budgets
* isolated session and principal binding
* closed action allowlist
* atomically reserved action, navigation, screenshot, byte, action-time, and
  session-time ceilings keyed to the binding, session, action, and idempotency
  key
* cancellation, emergency stop, healthy-state, and monotonic clock checks
* a first-attempt-only rule with no automatic retries

One browser driver call is permitted per runtime invocation. Caller-reset
counters cannot replace the repository's authoritative state. The runtime
validates the exact reservation transition and re-evaluates the signed scope
at the final pre-driver clock observation before calling the driver. Safety is
refreshed after confirmed reservation and before that clock observation. Expiry
or an adverse safety change during preflight or budget reservation rejects the
action with zero driver calls; the scope decision does not allocate a second
budget reservation.
The runtime validates the
exact completion transition afterward. It rejects results that report retries,
cross-origin movement, session drift, principal drift, script evaluation,
arbitrary file access, uploads, downloads, clipboard use, extensions, pop-ups,
incomplete actions, or exceeded ceilings.

## Evidence and outcomes

Every invocation returns a content-addressed receipt and a chained, content-addressed transcript. Terminal states distinguish:

* rejection before the driver call
* injected driver failure
* postcondition failure after one driver call
* completed action

A completed receipt requires the exact terminal reason `completed`. The
constructor, strict verifier, and registry schema reject any other valid-shaped
reason for that terminal state.

Receipts record the intended origin, exact pre-action and post-action URLs and
origins, session attestations, counters, elapsed time, evidence references,
execution bindings, and content-addressed budget reservation and completion
evidence. Rejections before the driver call explicitly record that no browser
action occurred. Driver and postcondition failures preserve that one call
occurred without treating the action as successful.

The strict parser accepts canonical printable ASCII JSON, rejects duplicate or unknown keys and floating-point values, recomputes every transcript and receipt content address, and performs semantic round-trip validation. The accompanying schema uses JSON Schema Draft 2020-12.

## Explicit boundary

This module proves deterministic boundary behavior against injected test doubles. It does not prove a real browser, live target, credential store, network route, isolation host, or production monitoring integration. It grants no assessment authority and has no qualification effect.
