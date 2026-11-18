# Supplied Yosys Netlist Structural Delta

The GD-D18-S12 partial component compares two bounded, synthetic,
Yosys-style JSON netlists. It projects top-module public port shapes, cell
type counts, and output-bit cell-driver counts. The checked example is
[`examples/offline-yosys-netlist-delta-component.json`](../examples/offline-yosys-netlist-delta-component.json).

The field interpretation follows the [Yosys `write_json` format](https://yosyshq.readthedocs.io/projects/yosys/en/v0.49/cmd/write_json.html).
This component accepts only a bounded subset of that format and does not
verify that Yosys produced either input. It reports differences against a
caller-supplied approved cell-type list. A new or unapproved cell type is a
structural review item, not evidence of a hardware trojan. Equal bounded
shapes do not prove functional equivalence.

No synthesis, simulation, silicon measurement, device action, finding
publication, or agent qualification occurs. Independent verification replays
the separate original model.
