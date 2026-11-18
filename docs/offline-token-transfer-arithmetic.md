# Offline Token Transfer Arithmetic

This R0 component supports a narrow part of `AOE-GB-D10-S09`. It reconciles caller-supplied before and after balances for a declared successful, isolated, zero-fee transfer between two different accounts. A mismatch produces a review candidate only when the caller declares complete context.

The component does not query a token contract, transfer assets, verify events or establish total-supply conservation. Fees, rebasing, minting, burning, hooks, simultaneous transfers and self-transfers are outside its model. A supplied mismatch does not prove token loss or deployed behavior.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-token-transfer-arithmetic-component.json`](../examples/offline-token-transfer-arithmetic-component.json).
