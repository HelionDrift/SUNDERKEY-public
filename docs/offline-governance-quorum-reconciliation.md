# Offline Governance Quorum Reconciliation

This R0 component supports a narrow part of `AOE-GB-D10-S11`. It compares caller-supplied declared proposal outcomes against explicit quorum and approval arithmetic. Supported quorum bases are for votes only, for plus abstain, and all supplied votes. Supported approval rules are strictly more for than against, or a threshold share of decisive votes. A complete supplied snapshot and a determinable approval result are required for a candidate.

[OpenZeppelin Governor documentation](https://docs.openzeppelin.com/contracts/5.x/api/governance) shows that governance counting and quorum behavior are configurable. This component implements only its declared arithmetic, not a specific deployed Governor. It does not query a chain or account for delegation, custom counting, vetoes, timelocks or execution. A mismatch is a contradiction within supplied records, not proof of governance abuse.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-governance-quorum-reconciliation-component.json`](../examples/offline-governance-quorum-reconciliation-component.json).
