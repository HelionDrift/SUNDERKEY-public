# Offline Model Output Similarity

This R0 component supports `AOE-GD-D20-S05` with an exact, supplied-digest comparison. It does not query, copy, train, or evaluate a model. A caller supplies the same challenge IDs and SHA-256 output digests for a reference, a suspected candidate, and an independent control. The component counts exact matches to the reference and measures the candidate's excess match rate over the control using integer basis-point arithmetic.

The component returns a review candidate only when the declared conditions are comparable, the minimum challenge count is met, and the excess rate exceeds the caller's stated threshold. It returns `unknown` when those prerequisites are missing. Output text and output digests are not included in the report, which retains only match Boolean values, counts, a source-model digest, and a source-bound report address. Verification requires the separately retained original model.

This comparison cannot establish model theft. Common answers, shared training data, challenge selection, normalization differences, and an unsuitable control can change the result. The input digest provenance is not authenticated. The result cannot publish a finding, qualify a specialist, or approve positive use.

Example: [`examples/offline-model-output-similarity-component.json`](../examples/offline-model-output-similarity-component.json).
