# Offline Assessment Scenario Harness

`sunderkey.offline_assessment_scenario_harness` runs a fixed sequence of eight
local observation checkpoints. It is an adversarial mission-control fixture,
not a target executor or a production action-admission service. It complements
the existing 11-stage end-to-end conformance contract by checking how a
simulated mission responds when control signals change between stages.

## Checkpoints

The sequence is intake, admission, pre-dispatch, dispatch acknowledgment,
evidence, review, report, and pre-publication. Each callback receives a
`ScenarioProbe` containing the checkpoint, plan content address, prior
observation address, and remaining budget. A callback returns a structured
`ScenarioObservation`. The harness checks the bound tenant, source content
address, authority epoch and active state, fence epoch, health state, and
checkpoint-specific requirements before advancing.
Admission must be affirmed again at pre-dispatch and pre-publication; an
explicit denial at any checkpoint stops the sequence.

Only the accepted pre-dispatch gate records one **simulated** dispatch. Only
an entirely passing sequence records one **simulated** positive publication.
Neither event invokes an action or publication API. A denial terminates the
sequence before any later callback. Lost or duplicate acknowledgments never
trigger an automatic retry.

## Adversarial Coverage

The tests exercise authority revocation between admission and dispatch,
health pause before dispatch, lost and duplicate acknowledgments, stale source
content, cross-tenant handoff, stale fence, reviewer or evidence mismatch,
budget overrun, callback failure, receipt tampering, and restart. A restart
with a prior simulated dispatch requires reconciliation. A previously
completed or denied plan is never automatically replayed.

The maximum callback count is eight. The `Budget` ceiling from the plan is
checked after every observation. A budget overrun stops the sequence before
the next callback. Each observation and final receipt is content-addressed.
`verify_scenario_receipt` recalculates recorded gate decisions, budget use,
simulated counters, and receipt integrity without invoking callbacks.

## Example Integration

Create a `ScenarioPlan` with a bound `ExecutionBinding`, source digest,
authority and fence epochs, independent reviewer reference, and budget. Pass
one inert observer callable for each `Checkpoint` to `run_scenario`. Store the
returned receipt with the corresponding plan and, for a restart receipt, its
prior receipt. Verify with `verify_scenario_receipt` before using the record as
offline test evidence.

The callback boundary is intentionally narrow. Production adapters must not
be supplied to this harness. It does not call `MissionStore`, the action
executor, an API, a browser, a network client, a scanner, or a credential
provider. A callback is external code and must be an inert test double. The
harness cannot attest to side effects caused by a malicious or misconfigured
callback.

## Evidence Limits

`simulated_complete` means only that caller-supplied observations passed this
offline contract. It is not authorization, qualification, live service proof,
target safety proof, independent human review, or evidence that a finding was
published. The receipt states `qualification_effect: none`,
`proof_scope: repository_only_injected_scenario`, and no operational effects.
Actual deployment and live mission conformance require separate current
authority, target-health, admission, execution, custody, and review controls.
