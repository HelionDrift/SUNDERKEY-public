# Offline Wallet Threshold Authorization

This R0 component supports a narrow part of `AOE-GB-D10-S06`. It compares caller-supplied custody action outcomes with an explicit eligible-signer threshold. Repeated approvals from one signer count once, and unknown signers do not count. A review candidate requires a declared authorized action below the threshold, a caller-declared current policy, and complete approvals.

The component does not verify signatures, policy provenance, smart-account code, timelocks, recovery rules or deployed wallet behavior. It does not contact a wallet or move assets. A supplied threshold mismatch is not proof that an action executed, and other policy constraints may apply even when the threshold is met.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-wallet-threshold-authorization-component.json`](../examples/offline-wallet-threshold-authorization-component.json).
