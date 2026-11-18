# Offline MEV Trade Order Pattern

This R0 component supports a narrow part of `AOE-GB-D10-S10`. It checks a bounded caller-supplied order of trades in one declared pool for same-actor outer trades around a declared victim trade. The first outer trade must match the victim's direction and the later outer trade must reverse it. A complete sequence is required for a review candidate.

The component does not inspect a mempool or chain, model transaction bundles, prices, quantities, gas, liquidity or private orderflow. An ordering pattern does not establish intent, profit, front-running or harm. The actor and victim labels are caller-supplied.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-mev-trade-order-pattern-component.json`](../examples/offline-mev-trade-order-pattern-component.json).
