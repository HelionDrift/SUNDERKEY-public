# Offline Serverless Event Declarations

This R0 partial component compares bounded, caller-supplied function and event-source
identifier bindings. It neither invokes functions nor observes event delivery. A
discrepancy is an unsigned candidate about the supplied declarations only. This
component does not complete the Serverless Functions and Events specialist or grant
live use, qualification, or publication authority.

Ownership is profile `AOE-GC-D15-S13`, capability `army.gc.d15.s13`, vector
`AV-GC-D15-S13-01`, work package `IWP2-AOE-GC-D15-S13`, wave `IW2-015`, commander
`AOE-GC-D15-CMD`, group owner `AOE-HQ-05`, and independent validator `AOE-HQ-19`.
The bound blueprint is
`sha256:abe07d9922542325f8ff64c18646102de053dbd939e7f42dcad88492e7c62c12`.

## Supplied Declaration

The native model contains exactly `schema_version`, `source_id`,
`inventory_complete`, `functions`, and `event_sources`. Each function has a
unique `function_id` and unique `event_source_ids`. Each event source has a
unique `event_source_id` and one `target_function_id`. These are generic
identifier declarations, not a provider event-map parse. The example is
synthetic dispatcher input.

At most 64 functions, 64 event sources, and 256 declared function-event
bindings are accepted. Source and report ceilings are 64 KiB and 128 KiB.
The shared declaration core also bounds JSON nodes, depth, and string lengths.
Extra fields, duplicate IDs, and non-native types are outside the closed
software subset. They are not claimed invalid for any serverless provider.

## Checks and Evidence Boundary

With a complete supplied inventory, each function-to-event and event-to-function
identifier binding must agree reciprocally. A conflict yields
`candidate_supplied_binding_mismatch`. An incomplete inventory yields `unknown`
and no candidate mismatches. An empty, noncontradictory inventory also yields
`unknown`. Matching nonempty declarations yield only `supplied_binding_consistent`,
not a finding about real event delivery or authorization.

`analyze_supplied_serverless_event_declarations(model)` returns a detached,
addressed `ServerlessEventDeclarationReport`. The corresponding `verify_`
functions for the wrapper and exported bytes reconstruct the report against a
separately supplied original model. No network, provider, filesystem, process,
credential, target, publication, or qualification effect occurs.
