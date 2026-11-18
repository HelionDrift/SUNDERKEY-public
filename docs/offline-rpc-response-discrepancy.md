# Offline RPC Response Discrepancy

This R0 component supports a narrow part of `AOE-GB-D10-S12`. It groups bounded, caller-supplied response digests by chain, block reference, method and parameter digest. A review candidate requires distinct result digests attributed to different supplied endpoints, plus declared complete context and finalized blocks. Differences reported by one endpoint alone do not become a cross-endpoint candidate.

The component does not issue RPC requests, verify block finality, authenticate endpoints or canonicalize responses. Different digests can arise from differing encodings, stale observations or incorrect caller labels. A candidate does not prove a ledger inconsistency or malicious node.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-rpc-response-discrepancy-component.json`](../examples/offline-rpc-response-discrepancy-component.json).
