# Supplied SIS and BPCS Resource Projection

The GD-D19-S05 partial component compares identifiers in a bounded synthetic
Safety Instrumented System (SIS) and Basic Process Control System (BPCS)
declaration. [NIST SP 800-82r3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-82r3.pdf)
describes SIS functions in terms of sensors, logic solvers, and final control
elements, and notes that SIS independence and integrated safety architectures
vary. The checked example is
[`examples/offline-sis-bpcs-resource-component.json`](../examples/offline-sis-bpcs-resource-component.json).

The component checks that each declared path has bounded resource identifiers,
then counts and hashes identifiers shared across the two paths. Shared IDs
are prompts for engineering review, not proof of a defect. No overlap does
not prove independence, failure behavior, or functional safety. The source
and field configuration remain unverified. Independent verification replays
the separate original model. No controller or process equipment is contacted,
and no finding or qualification is produced.
