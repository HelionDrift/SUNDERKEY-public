# Offline telemetry ingest chain

`sunderkey.offline_telemetry_ingest_chain` replays up to 64 typed defender
telemetry batches, with at most 8,192 events, as one historical source chain.
It requires a stable binding, strictly advancing import times, contiguous
source sequence numbers within and across batches, and no repeated source
event reference, raw-event digest, envelope digest, or batch digest. This
extends the adapter's per-batch and active replay-window checks with an
all-history local replay check.

The first supplied sequence may be any valid source sequence. The chain
cannot prove that earlier source events never existed or that an external
producer did not omit events before the first supplied batch. It also cannot
authenticate source custody, prove live currentness, collect telemetry,
persist state, or grant execution or qualification. Its output explicitly
records these limits and carries only binding, batch, sequence, and count
digests, not raw telemetry.

Run the focused local check from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_offline_telemetry_ingest_chain -v
```
