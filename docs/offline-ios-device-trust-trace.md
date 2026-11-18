# Supplied iOS Device-Trust Trace Policy

The GB-D08-S08 partial component compares synthetic device-trust state labels
with a supplied test policy. Its checked example is
[`examples/offline-ios-device-trust-trace-component.json`](../examples/offline-ios-device-trust-trace-component.json).

No iOS device is connected, no jailbreak action is attempted, and no trust
state is changed. The model accepts no exploit, payload, or device command.
State labels and completeness are assertions, not proof of device privilege.
This is nonqualifying R0 evidence and grants no authority.
