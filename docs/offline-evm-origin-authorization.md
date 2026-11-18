# Offline EVM Origin Authorization

This R0 component supports a narrow part of `AOE-GB-D10-S01`. It compares caller-supplied labels for transaction origin, immediate caller, the principal used by an authorization check, and the declared decision. A review candidate requires a declared authorized action gated by transaction origin while origin and immediate caller differ. Incomplete context remains unknown.

The component does not parse Solidity or bytecode, execute an EVM trace, verify principal identity or query a chain. Other checks may be present. A supplied origin-based label is a review signal, not proof of phishing, exploitability or access-control failure.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-evm-origin-authorization-component.json`](../examples/offline-evm-origin-authorization-component.json).
