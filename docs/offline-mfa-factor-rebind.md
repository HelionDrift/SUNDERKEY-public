# Supplied MFA Factor Rebind Projection

This R0 offline component adds partial algorithm coverage for specialist
`AOE-GA-D03-S02`, capability `army.ga.d03.s02`, vector
`AV-GA-D03-S02-01`, work package `IWP2-AOE-GA-D03-S02`, and wave `IW2-003`.
The domain commander is `AOE-GA-D03-CMD`, and independent validation is
assigned to `AOE-HQ-19`. It is not a completed candidate or qualified agent.

The version 1 model accepts only synthetic account, factor, source, and event
labels. A caller declares initial enrollment, whether approval is required
before a factor rebind, completeness, and a strictly ordered timeline of
approval, binding, revocation, and reported factor use. A binding without
the declared approval, duplicate binding, revocation of an unenrolled factor,
or reported acceptance of an unenrolled factor is a candidate declared
conflict. It is not proof of an actual authentication result or bypass.

The model is distinct from the supplied recovery-factor threshold component:
it compares lifecycle order and enrollment state, not factor counts. It is
also distinct from the privileged application MFA-path component, which
compares sign-in path declarations rather than factor changes.

Incomplete policy, event coverage, or ordering makes every disposition
unknown. The report does not authenticate an approval event, establish
factor possession, or infer whether another sign-in requirement was met.
`analyze_supplied_mfa_factor_rebind` emits an unsigned content-addressed
report. Verification replays a separately retained original model through
`verify_supplied_mfa_factor_rebind` or its bounded JSON-byte variant. The
embedded model cannot authenticate itself. A synthetic dispatcher input is
in [the component example](../examples/offline-mfa-factor-rebind-component.json).

No factor secret, one-time code, password, credential, service, or target is
read or contacted. No enrollment, recovery, authentication attempt, finding
publication, positive use, or qualification occurs.
