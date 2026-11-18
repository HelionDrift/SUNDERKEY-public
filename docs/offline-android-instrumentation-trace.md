# Supplied Android Instrumentation Trace Policy

The GB-D08-S02 partial component compares synthetic, content-free trace-state
transitions with a supplied test policy. Its checked example is
[`examples/offline-android-instrumentation-trace-component.json`](../examples/offline-android-instrumentation-trace-component.json).

No Android device or app is connected and no instrumentation is run. The
model accepts no hook, binary, payload, or device command. Declared states
and completeness are assertions, not runtime evidence. A mismatch does not
prove exploitation. This is nonqualifying R0 evidence and grants no authority.
