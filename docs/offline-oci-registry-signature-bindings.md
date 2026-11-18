# Offline OCI Registry Signature Bindings

This R0 partial component compares bounded, caller-supplied registry and
signature binding metadata. It does not fetch or authenticate a registry
artifact, read signature bytes, verify cryptography, establish signer identity,
or apply trust policy. A discrepancy is an unsigned candidate about the
declarations only. It does not complete the Registries and Image Signing
specialist or grant live use, qualification, or publication authority.

Ownership is profile `AOE-GC-D15-S11`, capability `army.gc.d15.s11`, vector
`AV-GC-D15-S11-01`, work package `IWP2-AOE-GC-D15-S11`, wave `IW2-013`,
commander `AOE-GC-D15-CMD`, group owner `AOE-HQ-05`, and independent validator
`AOE-HQ-19`. The bound blueprint is
`sha256:b9ac882cf604d5e988cf907d6ed19a1e10f43362d1f599efa92dfaf31bdaea9b`.

## Supplied Declaration

The native model contains exactly `schema_version`, `source_id`,
`inventory_complete`, `registry`, and `signatures`. The registry declaration
has a lowercase ASCII `host`, a bounded `repository`, and a lowercase SHA-256
`manifest_digest`. Each signature row has a unique `signature_id`,
`artifact_digest`, `subject_digest`, and `repository`. These are generic
declarations, not a parsed OCI referrer or signature envelope. The example
file is a synthetic dispatcher input.

At most 64 signature records are accepted. The source and report ceilings are
64 KiB and 128 KiB. The shared declaration core also bounds JSON nodes, depth,
and string lengths. Extra fields, duplicate IDs, non-native types, and other
digest algorithms are outside this closed software subset. They are not
declared invalid for OCI or any signature specification.

## Checks and Evidence Boundary

For a complete supplied inventory, each signature record's claimed subject
digest and repository are compared with the supplied registry target. A
conflict yields a `candidate_supplied_binding_mismatch`. An empty or incomplete
inventory yields `unknown`; incomplete rows retain null match values and
produce zero candidate mismatches. Matching rows yield only
`supplied_binding_consistent`, not a verified signature or trusted image.

`analyze_supplied_oci_registry_signature_bindings(model)` returns a detached,
addressed `OciRegistrySignatureBindingsReport`. The corresponding `verify_`
functions for the wrapper and exported bytes reconstruct it against a
separately supplied original model. No registry, network, filesystem, process,
provider, credential, target, publication, or qualification effect occurs.
