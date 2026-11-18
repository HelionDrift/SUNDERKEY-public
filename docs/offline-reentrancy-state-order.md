# Offline Reentrancy State Order

This R0 component supports a narrow part of `AOE-GB-D10-S08`. It accepts bounded, caller-supplied event traces for one declared state resource per trace. A candidate requires an ordered state read, external call, callback entry and later state write in the same trace. A write before the external call or a missing callback is kept distinct. Incomplete traces or absent state writes remain unknown.

The checked order reflects the concern behind Solidity's [Checks-Effects-Interactions guidance](https://docs.soliditylang.org/en/latest/security-considerations.html). The component does not parse source code, execute a contract, send a transaction, establish that a callback can reenter sensitive logic, or account for locks, rollback and invariants. Its event labels and completeness are unauthenticated caller declarations. A candidate is a review signal, not a confirmed reentrancy vulnerability.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-reentrancy-state-order-component.json`](../examples/offline-reentrancy-state-order-component.json).
