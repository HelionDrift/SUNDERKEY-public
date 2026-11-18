# Supplied macOS Launch-Job Policy Projection

The GC-D12-S11 partial component compares at most 64 synthetic user or
system launch-job declarations with caller-supplied approval IDs. Enabled
jobs outside that list are marked for review. Separate verification replays
the original supplied model.

Jobs, approval, enabled state, and completeness are unverified assertions.
The component does not query launchd, execute a job, or prove persistence.
A mismatch is not a finding and grants no authority or qualification.

The checked synthetic example is
[`examples/offline-macos-launch-policy-component.json`](../examples/offline-macos-launch-policy-component.json).
