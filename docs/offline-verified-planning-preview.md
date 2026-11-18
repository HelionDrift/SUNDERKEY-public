# Offline Verified Planning Preview

`sunderkey.offline_verified_planning_preview` provides a separate, read-only
preview for one archived offline API planning bundle. The caller pins the exact
tenant, context, bundle digest, and scope digest. The caller also supplies the
original typed case sources, batch, verified scope, scheduling inputs, Army
registry, and optional target context through an exact native `planning_inputs`
dictionary.

The function first reconstructs and binds the complete local planning chain
from the entry-time original inputs. It then reads the archive through an
injected `PlanningBundleReader`, checks the returned tenant and context
binding, and compares its bounded, native JSON tree with that pre-reader
result. It also calls `verify_offline_api_planning_bundle` against the archived
bundle and the original inputs after the read, so changes made by the reader
fail closed. The archive tree is depth, node, and byte bounded before full
serialization. Unlike historical archive inspection, this rejects a
self-consistent archive built from different inputs. The output contains only
binding and component digests plus explicit safety flags. It does not disclose
case bodies, evidence, paths,
principal identities, task descriptions, or raw tenant and context IDs.

This is an offline provenance rehearsal, not a production trust decision.
The caller must independently authorize access to the exact tenant and context
before invoking the function. Caller-supplied originals and keys do not prove
external source custody. A successful replay does not prove that the scope,
sources, registry, or route remain current. The read and source replay are not
an atomic snapshot across independent systems. The result grants no action
authority or positive use. The module itself makes no network call, mutation,
finding publication, or target interaction. Its injected reader and reference
adapter analyzer can have effects that this function does not verify or
constrain, including network access. Deployments must provide appropriately
isolated, independently controlled implementations before treating a complete
invocation as effect-free.

The existing `POST /v1/planning/previews` route remains unchanged. It continues
to report historical integrity only, with `source_replay_performed: false`.
This new function is not exposed as an API route or production authorization
path.

Run the focused checks from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_offline_verified_planning_preview -v
python -m ruff check src/sunderkey/offline_verified_planning_preview.py tests/agents/test_offline_verified_planning_preview.py
```
