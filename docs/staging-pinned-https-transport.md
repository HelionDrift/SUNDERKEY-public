# Pinned HTTPS staging transport

`PinnedHttpsStagingTransport` is an opt-in network implementation for the
existing `ReferenceHttpBackend` interface. It is intended for controlled
staging exercises after the authorized HTTP runtime has admitted an action.
It does not resolve DNS, grant scope or action authority, acquire credentials,
or install itself in a worker. The repository test suite performs no target
network calls.

The caller supplies an exact HTTPS origin, a SHA-256 leaf certificate pin, a
set of literal connection IP addresses, request and response limits, and a
shared stop state. The runtime request must carry the same complete IP set.
The transport opens a socket to one pinned IP on port 443 without a second
name lookup. The default TLS context verifies the certificate chain and the
origin hostname. The transport then verifies the leaf certificate pin before
sending HTTP bytes. HTTP/1.1 is requested with ALPN. A mismatched certificate,
origin, peer address, request limit, or unsafe header fails closed.

There is one connection attempt, one HTTP request, no automatic redirect, and
no retry. Request and response header sizes are bounded. Response bodies are
read only up to the authorized limit plus one byte, so the surrounding backend
can mark an oversized response without retaining its full body. The shared
stop state is checked before connection, immediately before send, and during
bounded response reads. A stop cannot interrupt a blocking socket operation
faster than the configured timeout. Both timeouts are capped at ten seconds.
The staging request ceiling cannot exceed 1 MiB and the response ceiling
cannot exceed 8 MiB, regardless of caller configuration.
After-send failures are reported as uncertain and must not be retried without
new authority and settlement.

This is not a production-qualified adapter. It does not provide egress
firewall enforcement, mTLS or customer secret custody, durable idempotency,
external target health observation, signed dynamic conformance, or containment
host evidence. Those remain part of the D014 and adapter qualification path.
The code is deliberately not wired into the public API or automatic mission
execution.

Offline validation:

```powershell
$env:PYTHONPATH = 'src'
python -m unittest -q tests.agents.test_staging_pinned_https_transport
```

The tests replace the socket, TLS context, and HTTP connection with fakes.
They verify the literal IP, SNI, pre-send certificate rejection, stop behavior,
one-attempt semantics, redirect handling, and response bound.
