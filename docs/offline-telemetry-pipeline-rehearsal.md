# Offline telemetry pipeline rehearsal

`sunderkey.offline_telemetry_pipeline_rehearsal` accepts bounded in-memory
pages of already-supplied telemetry envelope references. It enforces one
continuous opaque cursor chain, an end marker only on the last supplied
page, at most 64 pages and 8,192 events, typed source binding, and the
existing freshness, normalization, and replay rules. It then replays the
cross-batch historical ingest chain, so source sequence gaps and all-history
replays also fail.

The normalizer is injected and should be pure. The module contains no source
client, network call, credential resolver, persistence, or collection loop.
Cursor and end-of-stream claims come from the caller, so a passing rehearsal
cannot prove that an external source supplied every page. The first cursor,
producer identity, custody, and live currentness remain unverified. The
result records only cursor references, batch digests, counts, and a chain
digest, without raw telemetry or positive-use authority.

Run the focused local check from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_offline_telemetry_pipeline_rehearsal -v
```
