# Offline Bridge Claim Replay

This R0 component supports a narrow part of `AOE-GB-D10-S04`. It groups a bounded caller-supplied ledger by source-chain message and destination chain. A review candidate requires more than one declared accepted claim for the same message and destination, plus caller-declared source finality and complete context. Unknown claim outcomes or absent finality leave the disposition unknown.

The component does not connect to a bridge, verify signatures or finality, inspect destination state, prove that assets were issued, or evaluate bridge-specific replay protection. Some systems record idempotent retries or distinct processing events for the same message, so duplicate accepted records can be false positives. The source payload digest is a supplied label, not authenticated evidence.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-bridge-claim-replay-component.json`](../examples/offline-bridge-claim-replay-component.json).
