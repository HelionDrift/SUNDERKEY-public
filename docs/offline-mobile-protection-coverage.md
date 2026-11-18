# Supplied Mobile Protection Coverage Projection

The GB-D08-S11 partial component compares supplied synthetic protection
coverage across at most 16 build variants, 32 modules, and 64 protection
declarations. For each variant and module, it reports protection kinds
required by the supplied model but absent from its declared coverage.
Supported abstract kinds are obfuscation, integrity checking, debug detection,
and runtime attestation. Separate verification replays the original model.

Requirements, build variants, modules, protection declarations, and inventory
completeness are unverified assertions. A gap is a planning mismatch, not an
observed weakness or bypass. The component does not inspect or deobfuscate a
binary, instrument an application, test a control, contact a target, grant
authority, or qualify a specialist.

The checked synthetic example is
[`examples/offline-mobile-protection-component.json`](../examples/offline-mobile-protection-component.json).
