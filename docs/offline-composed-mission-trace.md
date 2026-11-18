# Offline Composed Mission Trace

`sunderkey.offline_composed_mission_trace` creates a bounded, read-only
observation across an existing MissionStore audit snapshot, an expert workspace,
and the orchestration journal. It checks that the workspace belongs to the
requested mission and tenant, filters journal jobs to that mission or workspace,
and records source revisions and content addresses in a portable trace.

The mission audit is verified within one MissionStore read transaction. The
workspace store and orchestration journal are each verified locally before
their separate reads. Before returning, capture repeats the bounded job scan,
verifies the journal again, re-reads and verifies the workspace, and takes a
fresh mission audit snapshot. It rejects a changed relevant job, journal
event count or table count, workspace state or whole-store digest, or mission
revision or head. The second journal verification follows its second job scan,
so an observed journal write during that scan fails closed.

There is still no cross-store transaction. Another writer can change a source
after its final read, and sources can change between the independent reads.
The stability check detects observed movement, not an atomic snapshot or a
fresh authority attestation. The trace reports
`cross_store_consistency: not_proven` for that reason. Its own hash proves only
that the trace document has not changed. It does not authenticate the producer
or independently prove the source reports embedded in the document.
Replay parsing also checks the mission, workspace, tenant, and job links, so a
recomputed public hash cannot turn a cross-boundary document into a valid trace.

The scan is bounded to 1,000 tenant jobs and fails closed if the bound is
exceeded. An unrelated job is not included even if it belongs to the same
tenant. This is an operator review aid, not a complete operational timeline.

The trace does not create authority, perform target interaction, publish a
finding, dispatch a job, qualify an expert, or prove that a target action
occurred. Before any positive publication, admission, consumption, replay for
use, or execution, the responsible live boundary must recheck current sources
and authority. Finding custody, strategy-plan lineage, and actual adapter
execution are not part of this trace.

## Point-of-Use Selected Observation Recheck

`recheck_offline_composed_mission_trace` reparses a saved trace and requires
separately supplied expected tenant, mission, and workspace identifiers before
it reads current sources. It then recaptures from the supplied mission audit,
expert workspace, and orchestration journal. It compares the saved mission
revision and head, complete workspace observation, workspace-store digest,
journal schema digest, and relevant job observations. A changed selected field
fails closed. The comparison reads only and does not change any source store.

It deliberately does not require the complete mission-audit snapshot digest to
match. That digest includes the audit evaluation time and can change between
otherwise matching selected observations. The result reports whether that
digest changed, but does not explain why. Other mission-audit content,
time-sensitive authority, and unrelated journal jobs are not fully compared.
The only successful status is `selected_observations_match_at_recheck`, with
`full_mission_audit_state_compared: false`,
`source_identity_authenticated: false`, `current_authority_verified: false`,
`cross_store_consistency: not_proven`, and no positive-use or target effect.

The expected identifiers and source objects are caller supplied. The recheck
does not authenticate their producer, provide a cross-store transaction, or
guarantee they stay unchanged after the final read. It is a bounded review
aid, not a current authorization, complete operational timeline, or proof of
target execution.
