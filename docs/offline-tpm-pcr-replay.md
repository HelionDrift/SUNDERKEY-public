# Offline TPM PCR Replay

This R0 component supplies a narrow SHA-256 arithmetic slice of `AOE-GD-D24-S08`. It starts from a caller-provided PCR value and extends it with each supplied event digest in order, using `SHA-256(previous PCR || event digest)`. A mismatch against the caller-provided expected PCR is a review candidate only when the event sequence is declared complete. The [Trusted Computing Group's event-log processing guidance](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Guidance-Integrity-Measurements-Event-Log-Processing_V1.0_R131_PUB.pdf) describes replaying event digests into virtual PCR values.

The component does not parse a binary event log, authenticate event data, verify a TPM quote or nonce, inspect firmware, or read a live PCR. A matching supplied replay does not prove measured boot integrity or remote attestation.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-tpm-pcr-replay-component.json`](../examples/offline-tpm-pcr-replay-component.json).
