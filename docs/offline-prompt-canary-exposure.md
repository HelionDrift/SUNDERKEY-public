# Offline Prompt Canary Exposure

This R0 component supports a narrow part of `AOE-GD-D20-S12`. It scans explicitly supplied, bounded output text for an exact UTF-8 byte substring whose length and SHA-256 digest match a protected canary declaration. The canary value itself need not be supplied. It never contacts a model, target, provider, or retrieval system.

For each output, the report retains only its opaque ID, matching canary IDs, and a disposition. It does not re-emit output text, canary digests, or protected content. A match is a review candidate only when the caller declares the context complete and the protected canary distribution known. Otherwise the result is `unknown`. A nonmatch does not rule out partial, normalized, encoded, or paraphrased disclosure.

Canary placement, output origin, and authorization are not authenticated. Even an exact match does not by itself prove unauthorized system-prompt extraction. The source-bound report requires separate original-model replay and cannot publish a finding, qualify a specialist, or approve positive use.

Example: [`examples/offline-prompt-canary-exposure-component.json`](../examples/offline-prompt-canary-exposure-component.json).
