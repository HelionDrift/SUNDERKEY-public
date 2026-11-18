# Offline API access expectations

`sunderkey.offline_api_access_expectations` records a separate, content-addressed
set of caller-declared expected-access labels for one mission, target, scope,
object, and action. A binding replays a typed synthetic API case and checks
that every evidence principal has exactly one declared label, every declared
principal has evidence, and the evidence labels match the declaration.

This closes accidental label drift between a separately prepared assertion
set and the adapter's response evidence. It does not prove the assertion was
prepared before the observation. Its digest establishes content identity,
not identity, timing, ownership, customer authorization, or correctness of
the access policy. The output always records these limits and grants no
positive use, publication, execution, or qualification.

`bind_offline_api_retest_to_access_expectations` replays both distinct cases,
checks each against the same assertion set, and binds their retest comparison
to both case bindings. The matching verifier rejects a substituted assertion
set or changed output. It does not turn a synthetic observation change into
a verified fix or establish a pre-observation commitment.

The check is opt-in. Existing synthetic assessment and planning APIs remain
compatible, and a case without this binding must not be described as
independently access-policy-verified. Future production use would need
authenticated policy provenance and an independently verified
pre-observation commitment.

Run the focused local check from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_offline_api_access_expectations -v
```
