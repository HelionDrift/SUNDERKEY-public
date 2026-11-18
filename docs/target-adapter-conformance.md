# Target adapter conformance and offline references

## Purpose

Phase 207 provides repository-only reference adapters and deterministic
conformance evidence for target-facing infrastructure. It closes implementation
gaps between the existing authorized HTTP, target-session, target-health,
execution-control, and identity contracts without creating a second authority
path.

Nothing in this phase grants target authorization, qualifies a deployment, or
performs a live target interaction. Every reference transport is injected. The
repository tests use deterministic local fixtures only.

## Components

`target_adapter_conformance.py` defines a closed fourteen-requirement suite.
It records externally collected observations and creates a content-addressed
report. A passing report means only that the repository fixtures satisfied the
offline suite. The report fixes `authority_effect` and `qualification_effect`
to `none`, fixes `network_call_performed` to `false`, and fixes
`live_deployment_qualified` to `false`.

`reference_http_adapter.py` supplies three injected boundaries for
`execute_authorized_http_exchange`:

- a sequential deterministic DNS resolver that lets the existing runtime
  detect answer changes between preflight and send;
- a digest and length bound request-body provider;
- a one-attempt HTTP backend that requires exact HTTPS origin, SNI host,
  connected address, verified TLS evidence, certificate digest, request limit,
  and response limit bindings.

The HTTP reference never follows a redirect. A redirect response is returned as
redirect evidence to the existing authorized HTTP runtime, which rejects it.
Following the redirect requires a new normalized target, scope evaluation,
execution request, admission receipt, DNS check, and TLS check. This is redirect
reauthorization, not automatic redirect handling.

`reference_target_session_adapter.py` supplies an opaque credential-session
provider, deterministic revocation checker, and atomic single-use lease store
for `execute_authorized_target_session`. Only a `credref:` value reaches the
injected transport. No credential value, cookie, token, OTP, or challenge
answer is accepted or returned by any reference type.

An MFA or operator challenge produces a content-bound suspension reference and
the stable provider failure `operator_challenge_required`. It does not retry,
continue authentication, or approve the challenge. A separate operator flow
and a new authorized execution are required. Lease revocation remains enforced
by the existing target-session runtime before and after provider use.

`target_health_collector.py` accepts only a strict
`TargetHealthReceipt`. It chain-links each receipt, sends canonical bytes to an
injected signer, and publishes detached signature metadata. A rejected,
degraded, or unhealthy receipt produces a non-authoritative pause proposal.
Cancellation and emergency-stop state can also produce a pause proposal. The
proposal requests a control action but cannot perform one.

## Stop and cancellation behavior

The shared `AdapterStopState` is checked immediately before and after an
injected HTTP or session transport call. A pre-call stop prevents the call. A
stop observed during a call causes the adapter to reject the result and return
only a stable failure code through the existing runtime. Deployment transports
must also enforce cancellation at their own I/O boundary because a local check
cannot interrupt a blocked external implementation.

## Conformance requirements

The closed suite covers:

1. DNS rebinding rejection.
2. Exact TLS and origin binding.
3. Redirect reauthorization.
4. Request and response limits.
5. Cancellation and emergency-stop propagation.
6. Opaque session secret custody.
7. MFA and operator-challenge suspension.
8. Credential lease revocation.
9. Signed health chain continuity.
10. Pause proposals for adverse health.
11. Reuse of existing authority contracts.
12. Inability of an adapter to self-authorize.
13. Deterministic injected transport use in repository tests.
14. External live qualification.

The report schema is
`registry/schemas/target-adapter-conformance-report-v1.schema.json`. Signed
health observations use
`registry/schemas/signed-target-health-observation-v1.schema.json` and embed
the existing authorized target-health receipt schema.

## Deployment dependencies

Production use still requires separately authorized and qualified
infrastructure:

- isolated network namespaces and egress enforcement that workers cannot
  bypass;
- trusted DNS resolution with authenticated observations;
- TLS chain, hostname, certificate-policy, revocation, and time validation;
- streaming request and response limits enforced before material reaches the
  process;
- durable cancellation and emergency-stop delivery;
- an opaque secret broker and provider integration;
- operator challenge and MFA user interfaces;
- a durable atomic credential lease-use and revocation store;
- a hardware-backed or otherwise approved health signing service;
- durable chain custody, monitoring, alerting, and pause-control integration;
- independently approved target scope and action admission;
- live non-production conformance followed by independent qualification.

Repository conformance does not substitute for any of these dependencies.
