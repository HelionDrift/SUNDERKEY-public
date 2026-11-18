# Supplied Scheduled-Artifact Policy Projection

The GC-D12-S04 partial component compares at most 64 synthetic scheduled
artifact declarations with caller-supplied source and artifact allowlists. It
flags enabled declarations whose source label or artifact ID is absent from
the corresponding policy. Separate verification replays the original model.

Schedule, source, artifact, policy, and completeness are unverified assertions.
Labels are not parsed systemd units or crontab expressions. A mismatch does
not prove installed persistence. The component does not inspect a host,
install a task, start a service, or contact a target. It cannot grant
authority, publish a finding, or qualify the specialist.

The checked synthetic example is
[`examples/offline-scheduled-artifact-component.json`](../examples/offline-scheduled-artifact-component.json).
