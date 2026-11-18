# Offline Advisory Source Chain

The source-chain verifier checks an advisory transition against a closed, caller-supplied evidence set. It replays each asset reconciliation snapshot from raw asset observations, then both applicability reports from installed-component observations, then the transition report. A baseline snapshot may carry a bounded chain of earlier snapshots and raw observations. The current snapshot must be a direct descendant of the baseline snapshot.

## Input Contract

`AssetSnapshotSources` binds a baseline snapshot to its complete raw observation tuple, an expected observation-set digest, and an optional prior source segment. The current snapshot and its complete raw tuple are separate inputs. The caller must also provide the curated advisory, baseline and current installed-component tuples, both applicability reports, the transition report, and expected digests for the advisory, baseline and current snapshots, and each current or component raw set.

Obtain raw-set digests with `asset_observation_set_sha256` and `component_observation_set_sha256` when recording a trusted evidence manifest. Retain all expected digests outside the untrusted evidence bundle, especially the baseline snapshot digest that pins its entire prior chain. Passing a digest recalculated from the same untrusted input at verification time does not establish source completeness or authenticity. The verifier does not authenticate a feed, signer, observer, or manifest. It cannot prove that an upstream collector supplied every real-world observation.

The verifier rejects a missing, mutated, or substituted raw tuple when it differs from the retained pin, including when a replacement snapshot and report are internally coherent. It also rejects an omitted prior source segment, a snapshot not reproducible from its raw observations, altered tenant or snapshot lineage, a report not reproducible from its advisory and component observations, and a transition not reproducible from the two reports. Typed dataclasses are required throughout. Asset source ancestry is limited to 32 segments and raw sets are subject to the existing asset and component bounds.

## Output Boundary

`verify_advisory_source_chain` returns the original transition report only after all replay checks pass. It performs no network call, target interaction, scheduler action, authority grant, finding publication, execution, or remediation confirmation. A candidate match is not a confirmed vulnerability. A match no longer observed is not proof of remediation. Results have no qualification effect.

## Integration

The wrapper lives in `sunderkey.offline_advisory_source_chain`. An orchestrator should load and type-check the retained pins separately from the evidence bundle, construct `AssetSnapshotSources` for the baseline and its ancestors, and call `verify_advisory_source_chain` before displaying a transition as independently source-replayed. This module does not add a CLI or persistence path.
