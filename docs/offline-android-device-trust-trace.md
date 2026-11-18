# Supplied Android Device-Trust Trace Policy

The GB-D08-S04 partial component compares synthetic device-trust state labels
with a supplied test policy. Its checked example is
[`examples/offline-android-device-trust-trace-component.json`](../examples/offline-android-device-trust-trace-component.json).

No Android device is connected, no root action is attempted, and no trust
state is changed. The model accepts no exploit, payload, or device command.
State labels and completeness are assertions, not proof of device privilege.
This is nonqualifying R0 evidence and grants no authority.
