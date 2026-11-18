# Offline API policy and source attestation chain

`tests.agents.test_offline_api_dual_attestation_chain` composes two separate
local signatures over one synthetic API case. A producer key signs the
receipt-sourced evidence ledger. A different asserted policy-owner key signs
the expected-access labels. The test replays both signatures and requires the
signed policy binding's case-result digest to match the source ledger entry.
Changed ledger evidence or policy labels fail the chain.
The retest case checks a second receipt-sourced batch, a new producer-signed
ledger head, and the same signed policy assertion across both cases.

Run from the repository root with `PYTHONPATH=src`:

```powershell
python -m unittest tests.agents.test_offline_api_dual_attestation_chain -q
```

This test does not authenticate either real-world role, prove that the policy
signature preceded observation, establish a trusted source collector, or
grant positive use. It is a local cross-boundary regression, not evidence
that a customer target was assessed.
