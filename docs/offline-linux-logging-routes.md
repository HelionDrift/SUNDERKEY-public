# Supplied Linux Logging-Route Projection

The GC-D12-S08 partial component compares at most 64 synthetic stream routes
with caller-supplied required streams and sink states. It marks a required
stream with no declared enabled sink and leaves a missing required route
unknown. Separate verification replays the original supplied model.

Required streams, route bindings, sink states, and completeness are unverified
assertions. No log record is read, no sink is contacted, and no logging
control is changed. A declared gap does not prove impairment or establish a
finding. It grants no authority or qualification.

The checked synthetic example is
[`examples/offline-linux-logging-component.json`](../examples/offline-linux-logging-component.json).
