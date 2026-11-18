# Offline Seccomp and FHIR Common Task

The synthetic common task composes one bounded seccomp classic-BPF projection
with one privacy-minimal FHIR DeviceAssociation review. It exists to verify
that different specialists can contribute to the same task while retaining
their own commander assignments, source models, and original-model replay.

Both jobs are R0 dry runs with empty resource grants. A forbidden grant in
either job blocks the whole task. The reports are unsigned, nonqualifying
evidence. The task neither loads a kernel filter nor reaches a clinical
system, and it cannot authorize either operation.
