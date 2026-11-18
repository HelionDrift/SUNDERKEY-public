# Offline Membership Score Separation

This R0 component supports the membership-inference portion of `AOE-GD-D20-S06`. It accepts caller-supplied aggregate member and nonmember score arrays in integer basis points, a chosen threshold, minimum sample counts, and a minimum rate advantage. It calculates threshold-positive counts and the exact difference between the two positive rates using integer cross-products. No model or training record is accessed.

The result is `unknown` if the supplied score conditions are not declared comparable or either group is too small. A rate separation is only a review candidate. The threshold is caller-selected, and the component does not correct for selection bias, calibration, distribution shift, or multiple comparisons. It makes no individual membership inference and does not cover model inversion.

The report omits the score arrays and retains aggregate counts, exact rate numerator and denominator, a source-model digest, and a source-bound report address. Verification requires the original separately retained score model. It grants no finding, qualification, target authority, or positive-use approval.

Example: [`examples/offline-membership-score-separation-component.json`](../examples/offline-membership-score-separation-component.json).
