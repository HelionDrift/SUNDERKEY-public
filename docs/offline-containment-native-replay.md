# Offline containment native replay

The local OCI and microVM specifications are nonexecuting preparation
contracts. Their existing V1 domains, identifiers, command arguments, runtime
ports and nonqualifying effect declarations remain unchanged.

## Exact native intake

The specification, observation and fixture parsers require native dictionaries
with native string keys and the existing closed field sets. Nested collections
must be native dictionaries or lists. Primitive values may be native strings,
integers, booleans or null only where the existing profile permits them. These
profiles contain no floating-point fields. Native subclasses, tuples and other
objects are rejected without calling their conversion or comparison hooks.

Native collection validation runs before canonical serialization or hashing.
Each validation walk visits shared containers once and rejects cycles, without
treating a Python container graph as a serialized JSON document. Existing
semantic checks still decide whether each value belongs in its position. This
is not a general input size guarantee or an isolation boundary against code
running in the process.

Every V1 schema version is a native integer equal to 1. Reconstructed normative
control maps require matching types as well as matching values. For example,
`rootless: 1` is not `rootless: true`, `smt: 0` is not `smt: false`, and
`memory_mib: 512.0` is not the native integer `memory_mib: 512`. Correctly
recomputing the original content address does not make these substitutions
valid. The microVM fixture's `output_bytes` and `log_bytes` must each be native
integer zero, not false or floating-point zero.

Observation assertions are checked as native string lists before sorting or
set construction. Specification references retain their existing V1 identifier
grammar. A malformed reference or assertion produces a contract validation
error before the document is hashed.

## Offline verification

`tests/agents/test_local_containment_native_replay.py` reuses the genuine
Phase 169 fixture builders and exact checked repository inputs for current-source
native intake checks. Test-local fixture classes keep the original Phase 169
class state unchanged. Their manifest source digests and plan bindings must match
the actual checked source bytes. Its controls include:

- literal historical golden specification and fixture identities;
- exact current-source manifest and plan bindings;
- native JSON round trips with identical canonical documents;
- coherently readdressed boolean/integer and integer/float substitutions;
- nested fixture substitutions with recomputed specification, observation and
  fixture addresses;
- exact schema versions and zero counters;
- nonnative collection, string and integer subclasses rejected before hashing;
- malformed assertion and specification-reference fields;
- cyclic, deep and shared native input graphs rejected before serialization;
- caller-source collection isolation after restoration; and
- unchanged false execution/proof flags and all four operational effects set
  to `none`.

The test graphs and hook objects are inert local fixtures. No Podman,
Firecracker, jailer, process, socket, cloud provider, target or credential is
invoked. Existing Phase 169 schema and runner-adjacent tests remain applicable.

The literal historical golden test is deliberately separate from the current
checked-source fixtures. It constructs test-only, in-memory catalog metadata
with the fixed original reference source digest
`sha256:65b7ba1bbbd4b0131707e378bb6194bab0c07cb3455bff9b7db2f3798d931e62`,
the unchanged approved strategy and blueprint inputs, and the original synthetic
invocation, attestation, limits, bindings and timestamps. Genuine public
containment builders must still reproduce the original literal addresses.
No reference analyzer or runtime executes. This metadata does not claim the
historical source is current, patch a loader, or rewrite checked catalogs,
signed approvals or old artifacts. Legitimate current source and manifest
rebinding may change current fixture addresses without changing these
historical parser vectors.

## Unchanged external boundary

Passing these checks proves only consistency of the repository preparation
contracts. It does not authenticate the declared host, component, image, kernel,
root filesystem, service identity or containment observation. It does not prove
current host state, cancellation, cleanup, teardown or isolation. No runtime
adapter is activated and no permission is granted.

Exact deployed component and configuration pins, host preflight, authenticated
dynamic conformance, real execution evidence and independent qualification
remain external requirements under the existing D016 and authority contracts.
This repair adds no deployment, qualification, routing or target authority and
does not select any pending production deployment policy.
