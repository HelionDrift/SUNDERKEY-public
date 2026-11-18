# Offline Firmware Tamper and Provenance Projection

This R0 component covers a narrow declaration-only slice of `AOE-GD-D18-S16`.
It compares caller-supplied component provenance digest labels and tamper-seal
states with caller-supplied expected labels. A difference is an unsigned
declaration-gap candidate. Missing digests, unknown seal state, or incomplete
inventory or component context produces `unknown`.

The component does not inspect a device or package, authenticate a supplier,
or prove tampering or counterfeit origin. It establishes neither physical
impact, exploitability, a finding, nor qualification. Replay verification
requires the separately retained original model.

The [synthetic example](../examples/offline-firmware-tamper-provenance-component.json)
uses fictitious component declarations and no target resources.
