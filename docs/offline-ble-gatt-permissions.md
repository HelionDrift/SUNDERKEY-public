# Supplied BLE GATT Permission Projection

The GC-D13-S09 partial component compares at most 64 synthetic
characteristic access declarations with 32 supplied service IDs and 16
caller-defined sensitivity policies. It reports encryption or authentication
controls that the supplied policy requires but the characteristic declaration
does not include. Read, write, and notify labels are abstract operations in
this model. Separate verification replays the original model.

Services, characteristics, operations, policies, and security states are
unverified assertions, not discovered Bluetooth behavior. A mismatch does
not prove actual GATT access or a vulnerability. The component does not
connect to a device, use a radio, discover a service, exercise a
characteristic, contact a target, grant authority, or qualify a specialist.

The checked synthetic example is
[`examples/offline-ble-gatt-component.json`](../examples/offline-ble-gatt-component.json).
