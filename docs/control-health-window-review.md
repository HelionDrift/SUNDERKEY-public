# Offline Control Health Window Review

`sunderkey.control_health_window_review` adds a repository-only V9.10 check
alongside the existing detection validation contract. It revalidates the
content-addressed contract, then compares caller-supplied control-health
declarations with the exact control, configuration, scope, action, and action
time window. It performs no SIEM query, provider call, network request,
control change, or target action.

## Declared Health Sources

Each declaration binds one objective and control to the exact contract
configuration, scope, and action digests. It states one of `operational`,
`degraded`, `unavailable`, or `unknown` over a bounded interval no longer than
24 hours and carries a source digest. Its own content address is recomputed.
The module does not authenticate the source, prove the control actually had
that state, or establish current health.

The review reports whether a declaration covers the complete action window.
Missing, partial, and conflicting overlapping intervals remain explicit.
Coverage and conflict are separate counts, so an incomplete window with
contradictory health claims reports both gaps. A contract
outcome labeled `effective` receives an additional review flag unless the
covering declarations consistently say `operational`. Even a consistent
`operational` declaration is only a caller claim, not verified effectiveness.
The report can be rebuilt from the original contract and declarations. Its
closed output schema is
`registry/schemas/control-health-window-review-v1.schema.json`.

## Remaining Boundary

Every result requires independent review and has no authorization, execution,
network, or qualification effect. Live V9.10 still requires authenticated
control inventory and health telemetry, time synchronization, authorized
action evidence, vendor integrations, trusted custody, and qualified replay.
