# Supplied Threat-Scenario Graph

The GA-D04-S01 component projects dependency order and evidence gaps from at
most 64 caller-supplied scenario stages. Each stage may name at most 16
prerequisites. All references must resolve within the supplied inventory, and
cycles reject. A transitive prerequisite marked missing blocks the planning
projection; an unknown prerequisite keeps it unknown.

All stages and evidence labels are assertions. The result does not establish
attack feasibility, target ownership, authorization, a finding, qualification,
or a completed specialist. It performs no target interaction.

The checked synthetic example is
[`examples/offline-threat-scenario-component.json`](../examples/offline-threat-scenario-component.json).
Verification requires replay against the separate original model.
