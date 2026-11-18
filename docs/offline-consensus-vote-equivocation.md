# Offline Consensus Vote Equivocation

This R0 component supports a narrow part of `AOE-GB-D10-S05`. It groups bounded, caller-supplied vote records by chain, validator, height, round and declared step. A review candidate requires distinct block identifiers for the same coordinate and a caller-declared complete context. Repeated records for one block do not form a conflict.

The component does not authenticate votes, verify signatures or validator-set membership, apply a particular chain's consensus rules, or query a node. Its generic step label is not a protocol-specific vote type. Conflicting caller-supplied labels do not establish signed equivocation or slashable conduct.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-consensus-vote-equivocation-component.json`](../examples/offline-consensus-vote-equivocation-component.json).
