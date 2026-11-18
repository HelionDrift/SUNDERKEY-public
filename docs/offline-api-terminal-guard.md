# Offline API Terminal Guard

`OfflineApiTerminalGuard` is an opt-in wrapper for one local
`LocalApiService`. It captures an owned canonical copy of each request before
inspection and delegation. A caller that explicitly uses the wrapper cannot
send a finding with status `accepted_risk`, `false_positive`, `remediated`, or
`closed`, or a remediation with `closure_status=closed`. Those requests raise
before `LocalApiService.handle` and before any authorizer, admission port,
repository read, or commit is called. Hashes, placeholder retest references,
and repeated idempotency keys do not create exceptions to this rule.

Recognized nonterminal requests are delegated with the same semantic request
binding. The wrapper does not independently grant access, approve a finding,
verify a retest, or determine that an open status is safe. The service's
injected authorizer, admitter, repository, and normal validation remain in
charge of delegated requests.

This module does not alter `LocalApiService` or its HTTP adapter. A caller
that invokes either directly can still publish a terminal-looking API record.
The guard therefore makes no production route-enforcement claim. It has no
trusted current finding source, authenticated reviewer binding, closure
approval, qualification effect, or target effect. A positive terminal path
requires an explicit versioned status and identity contract, fresh authority
and source currentness, and an independently authenticated closure decision.

Focused tests:

```text
python -m unittest tests.agents.test_offline_api_terminal_guard -v
```
