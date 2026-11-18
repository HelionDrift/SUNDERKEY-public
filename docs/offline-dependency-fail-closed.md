# Supplied Dependency-Failure Fallback Decisions

The `AOE-GE-D23-S12` partial specialist compares a declared deny-on-failure
policy with a caller-supplied dependency state, configured fallback decision,
and declared outcome. It only evaluates finite native observations. It does
not contact a dependency, cause a failure, or observe target behavior.

When complete declared premises say a dependency failed and both configured
fallback and outcome allow despite the deny-on-failure policy, the result is
only a `candidate_declared_fail_open_conflict`. Unknown dependency or decision,
incomplete policy or capture, and disagreement between a fallback and outcome
withhold that conclusion. The dependency state, configuration, and outcome
are unverified caller assertions. An apparent match is not a verified
fail-open path or authorization decision.

The native model accepts at most 128 observations within a 32 KiB source
bound. Dependency labels use opaque `ref:` syntax, which is a format guard
and not proof of data sanitization. The report embeds the original model for
separate-source replay and remains within a 64 KiB report bound. No file,
network, process, credential, target, publication, execution, or
qualification effect occurs. The
[synthetic example](../examples/offline-dependency-fail-closed-component.json)
contains declared outcomes only.
