# Offline Mission Conformance Checkpoint

`sunderkey.offline_mission_conformance_checkpoint` adds a restart boundary to the
existing end-to-end conformance harness. It accepts content-addressed stage
evidence supplied by a caller, validates each ordered prefix, and produces a
canonical checkpoint document that can be saved and restored outside the
process. The module does not invoke an adapter or persist a checkpoint itself.

## Scope

The checkpoint preserves the mission plan, tenant, context, scope, operator,
fence, idempotency key, stage order, version, budget, custody chain, control
links, and required independent reviews. `next_request` describes the next
offline observation expected by the existing conformance contract. `append`
accepts only a valid passed observation. `assess_completion` delegates to the
existing full conformance assessment and is unavailable until all eleven
observations have been validated.

A checkpoint is not action authority. Restoring it does not prove that a
previously current source is still current. Any use that could publish, admit,
consume, replay for use, or execute must perform fresh live-currentness checks
in its own authority boundary.

## Remaining Composition Gap

The current conformance stages cover service intake, dispatch, admission,
specialist execution, evidence, finding, reporting, activation, cleanup, and
rollback as injected observations. They do not yet operate the actual strategy
coordinator, expert workspace, MissionStore admission/executor, finding
lifecycle, or local API in one composed runtime. This checkpoint closes only
the offline restart and prefix-integrity gap. It does not establish a live
vertical slice or production qualification.

## Effects

The module performs no network, target, credential, deployment, or filesystem
operations. Callers are responsible for external checkpoint storage and for
obtaining genuine observations through independently authorized systems.
