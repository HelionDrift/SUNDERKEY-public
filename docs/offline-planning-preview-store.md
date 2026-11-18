# Local planning preview archive store

`SQLitePlanningBundleStore` is a concrete local reader for the offline
planning preview route. An operator-side `put` call imports an already-built
bundle after verifying its historical content and Army roster binding. The
API route itself only calls `get` and has no import or mutation operation.

The store uses an isolated SQLite file, a checked schema version, an exact
tenant and context lookup, and a globally unique bundle digest. Reimporting
identical bytes is idempotent; rebinding the same digest to another tenant or
context fails. Every read rechecks bundle integrity, including after a direct
database change. Local tests cover tenant isolation, corruption, schema
mismatch, concurrent idempotent imports, and the ASGI preview path.

This adapter is for local synthetic evaluation. It does not encrypt records,
provide production identity, replicate data, or satisfy D014 storage and key
custody requirements. Do not import live customer evidence into this local
store on the strength of its integrity checks alone.
