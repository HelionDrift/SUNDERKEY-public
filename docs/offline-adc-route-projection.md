# Supplied ADC Route Projection

The GC-D13-S16 partial component compares at most 16 synthetic listeners,
32 backends, and 64 routes. It projects declared public-to-private mappings,
public listeners without declared edge TLS, plaintext upstream hops after
declared edge TLS termination, and trusted
forwarded headers without declared validation. It also reports route pairs
whose path prefixes overlap under an explicitly defined segment-boundary
model. Separate verification replays the original model.

Listener, backend, transport, header, and route states are unverified
assertions. Prefix overlap is not vendor routing precedence. A projected flag
does not prove that a request reaches a backend or that any control fails.
The component does not inspect an ADC or CDN configuration, send traffic,
perform a TLS handshake, contact a target, grant authority, or qualify a
specialist.

The checked synthetic example is
[`examples/offline-adc-route-component.json`](../examples/offline-adc-route-component.json).
