# Offline enterprise provisioning currentness

`validate_provisioning_command` evaluates the supplied actor `RoleBinding` at
the explicit canonical UTC `evaluated_at` value. An active binding with the
required identity-administrator permission must also satisfy:

```text
valid_from <= evaluated_at < valid_until
```

The start is inclusive and the expiry is exclusive. An expired binding, expiry
equal to the evaluation time, or a future binding start produces a typed deny
decision containing `actor_binding_outside_validity`. The other tenant, actor,
status, permission, version, content-precondition and idempotency checks remain
in place. Ordinary `authorize` applies the same interval to its explicit
request time, using its existing `binding_outside_validity` reason.

## Injected dispatch boundary

`dispatch_validated_provisioning` already evaluates the command before invoking
any admission verifier, reservation store, dispatcher or completion store. A
deny decision therefore invokes none of those callbacks and creates no
reservation. No new callback, clock read, automatic retry or fallback is added.

Valid active bindings and start-time equality retain the existing allow
decision and admission, result and receipt identities. The existing atomic
idempotency store still rejects reserved or completed keys. Once a dispatch
has occurred, a failed dispatcher, malformed postcondition or completion
failure still leaves the reservation held rather than silently retrying the
effect. A later attempted use with a binding outside its supplied evaluation
interval is denied before the replay or dispatch ports.

## Historical metadata and limits

This is a supplied-time consistency check, not a live clock observation or a
claim about authority at a later instant. It does not authenticate role data,
replace the explicit admission verifier, or establish identity-provider or
dispatcher trust. Callers remain responsible for supplying the intended
evaluation time and authenticated inputs at their authorized boundaries.

Historical binding metadata can still be constructed, inspected and serialized
with its original content address after expiry. That inspection is not fresh
provisioning admission. No record schema, hash domain, authority operation,
directory content or effect vocabulary changes.

The runtime remains limited to explicitly admitted test or staging dispatch
through injected ports. There is no built-in network or provider client,
credential value, production authority, directory payload, deployment or
qualification claim.

## Regression evidence

`tests/agents/test_enterprise_provisioning_currentness.py` reuses the existing
pure Phase176 fixture and inert ports. It covers expired, equal-expiry and
future-start denials with zero callback counts; active and start-equality
controls; reciprocal ordinary authorization decisions; seven pre-change native
document hashes and valid identities; unchanged historical serialization; and
the existing atomic replay boundary followed by an expired-actor denial. The
Phase162 and Phase176 suites retain their compatibility, no-retry and
nonproduction controls.
