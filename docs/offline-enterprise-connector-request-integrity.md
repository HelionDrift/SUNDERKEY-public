# Offline enterprise connector request integrity

This repair closes a pre-transport request-mapping gap in the existing Jira,
Microsoft Sentinel and Security Copilot contracts. It does not add a connector,
change the vendor snapshot or API versions, resolve an endpoint or credential,
make a provider call, deploy a service or establish delivery authority.

## Source-bound mapping before transport

The public delivery function first reconstructs the supplied native binding and
request through their existing constructors. It rebuilds the expected request
using the existing vendor mapper, the binding, the request's event projection,
and its original idempotency key and time window. Canonical documents must match
before any transport callback.

A safely serialized, correctly rehashed generic POST is not sufficient. An
unselected path, body from another vendor, changed Jira route, substituted
Sentinel event field or changed Copilot specification digest is rejected before
the callback, even when the request still declares the original binding and
event. A legitimately changed supplied binding or event requires the vendor body
to be rebuilt from that input.

Binding and request parsers compare reconstructed canonical documents, not
Python equality. Their schema version must be the native integer `1`. Boolean,
floating-point and integer-subclass aliases cannot silently normalize to the
unchanged native record identity.

The parser alone has no external binding with which to replay a vendor mapping.
It therefore continues to validate content, shape and declared identity. A
generically valid request may parse yet fail delivery when the actual supplied
binding does not produce its path and body.

## Preserved behavior and limits

Valid binding and request IDs, hash inputs, API versions, mappings, status
normalization and validity windows are unchanged. Valid delivery makes exactly
one call to the explicit injected transport. There is no automatic retry,
credential resolver, network client, timer or outbox mutation.

The supplied binding and event remain caller declarations. Reconstruction and
hash equality do not authenticate their source, establish vendor consent or
permission, prove that an event occurred, or verify an actual external write.
The callback is an external trust boundary; this repair is not isolation from
arbitrary malicious code in the same process and does not undo an external
effect. Real connector completion still requires the external evidence listed
in the existing enterprise connector guide.

## Regression evidence

Tests use the existing Phase 166 native fixtures and inert `FakeTransport` only.
They reproduce all six rehashed wrong-path and wrong-body requests across the
three vendors. These requests preserve their binding and event and successfully
parse native JSON, but delivery rejects them with zero callbacks.

Additional checks cover cross-vendor bodies, mismatched event projections,
changed route sources, unrehashed tampering, noncanonical body JSON, native
schema aliases and direct native record inconsistencies. Valid round trips
preserve all three prior binding/request identity goldens. Positive controls
retain one-call success, retryable/permanent status normalization and the
original validity-window behavior without using live services or secrets.
