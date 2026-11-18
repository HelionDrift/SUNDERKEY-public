# Offline Firmware Debug Interface Inventory Projection

This R0 component covers a narrow declaration-only slice of `AOE-GD-D18-S05`.
It compares caller-supplied enabled-state policy with caller-supplied
enabled-state labels for UART, JTAG, and SWD interfaces. A difference is an
unsigned policy-gap candidate. Missing state or incomplete inventory or
interface context produces `unknown`.

The component does not probe, enumerate, connect to, or enable any interface.
It establishes neither physical accessibility, authentication, exploitability,
a finding, nor qualification. Replay verification requires the separately
retained original model.

The [synthetic example](../examples/offline-firmware-debug-interface-inventory-component.json)
uses fictitious interface declarations and no target resources.
