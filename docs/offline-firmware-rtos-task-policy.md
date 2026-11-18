# Offline Firmware RTOS Task Policy Projection

This R0 component covers a narrow declaration-only slice of `AOE-GD-D18-S04`.
It compares caller-supplied task priorities and isolation labels against
caller-supplied expected policy. A difference is an unsigned policy-gap
candidate. Missing declared state or incomplete inventory or task context
produces `unknown`.

The component does not execute an RTOS, inspect a scheduler, prove memory
isolation, contact hardware, or use credentials. It establishes neither actual
runtime behavior, exploitability, a finding, nor qualification. Replay
verification requires the separately retained original model.

The [synthetic example](../examples/offline-firmware-rtos-task-policy-component.json)
uses fictitious task declarations and no target resources.
