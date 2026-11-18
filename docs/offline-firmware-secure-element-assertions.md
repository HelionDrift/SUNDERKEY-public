# Offline Firmware Secure Element Assertions Projection

This R0 component covers a narrow declaration-only slice of `AOE-GD-D18-S10`.
It compares caller-supplied expected and supplied identity digests and
hardware-backing labels for TPM, TEE, and secure-element assets. A difference
is an unsigned assertion-gap candidate. Missing labels or incomplete context
produces `unknown`.

The component does not perform attestation, read keys, contact a secure
element, or prove a hardware root of trust. It establishes neither key
protection, exploitability, a finding, nor qualification. Replay verification
requires the separately retained original model.

The [synthetic example](../examples/offline-firmware-secure-element-assertions-component.json)
uses fictitious identity digests and no target resources.
