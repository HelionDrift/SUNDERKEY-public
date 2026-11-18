# Supplied dependency resolution collision projection

This R0 partial component belongs to existing specialist `AOE-GC-D17-S08`,
capability `army.gc.d17.s08`, vector `AV-GC-D17-S08-01`, package
`IWP2-AOE-GC-D17-S08`, and wave `IW2-020`. It adds partial A7.4 offline
evidence only. It does not complete the specialist, a qualification gate, or
approval for live use.

## Supplied model and candidate rule

`analyze_supplied_dependency_resolution(model)` accepts exact native schema
version 1 with a model source ID, an `evidence_complete` boolean, and three
separately identified sources. The manifest declares registry IDs and exact
package names with intended registry references. The lockfile supplies a
selected name, version, registry reference, and artifact SHA-256 for each
requirement. Resolution records supply the selected package and a bounded list
of available packages. Names and versions are opaque exact strings; the
component does not implement ecosystem naming, version constraints, registry
priority, or package-manager resolution rules.

A `collision_candidate` requires the caller to declare evidence complete, the
manifest and lockfile names to agree with the supplied selection, the lockfile
and selected resolution to agree on version and registry, the selected package
to appear in the supplied available list, and the exact package name to appear
there under both the intended and selected registries. The selected registry
must differ from the intended one. This is a candidate about the supplied
records, not a dependency confusion or malicious-package verdict.

Missing lock or selection evidence, an incomplete-evidence declaration, or no
supplied same-name package from the intended registry yields an `unknown`
disposition. Disagreement among manifest, lockfile, resolution selection, and
available records yields a `source_conflicts` entry instead of a candidate.
Same-registry selection is a negative result for this narrow check, not proof
that the build is safe.

## Replay and boundary

The report retains the supplied model, source IDs and SHA-256 addresses,
deterministic per-requirement outcomes, collision candidates, unknowns,
conflicts, and uncertainty. `verify_supplied_dependency_resolution` rederives
the report against a separately supplied original model. The checked synthetic
component envelope is
`examples/offline-dependency-resolution-component.json`.

The analyzer never fetches or installs a package, contacts a registry, starts
a process, resolves credentials, or interacts with a target. Supplied registry
identities and completeness are not authenticated. No live registry behavior,
attack, exploitability, or impact is inferred.
