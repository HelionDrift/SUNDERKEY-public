# Offline Firmware Update Metadata

This R0 component provides a bounded, caller-supplied UEFI EFI System Resource Table (ESRT) device-firmware comparison for `AOE-GD-D24-S09`. It compares each proposed UINT32 version with the supplied resource's `LowestSupportedFwVersion` and reports its direction relative to the supplied `FwVersion`. A version below the declared rollback floor is an unsigned review candidate, not a conclusion that an update would be accepted, rejected, or exploitable. A proposal targeting a different `FwClass` is unknown rather than a mismatch finding.

The [UEFI Specification 2.10, Firmware Update and Reporting](https://uefi.org/specs/UEFI/2.10/23_Firmware_Update_and_Reporting.html) defines ESRT `FwClass`, `FwType`, `FwVersion`, `LowestSupportedFwVersion`, and last-attempt fields. The latter are included as supplied metadata without treating them as evidence of a current update attempt. [NIST SP 800-193](https://csrc.nist.gov/pubs/sp/800/193/final) provides the wider platform firmware protection, detection, and recovery context. This component does not implement those mechanisms.

The model covers one ESRT device-firmware resource (`FwType` 2) and at most 64 proposals. It never reads an ESRT table, parses a capsule, verifies a signature, contacts a device, stages or flashes firmware, or establishes device state. It does not interpret vendor-specific version encoding beyond the supplied numeric ordering or infer actual rollback enforcement. Its unsigned report requires a separately retained original model for replay, and grants no finding, qualification, or positive-use authority.

Example: [`examples/offline-firmware-update-metadata-component.json`](../examples/offline-firmware-update-metadata-component.json).
