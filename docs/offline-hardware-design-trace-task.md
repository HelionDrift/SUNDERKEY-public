# Supplied Hardware Design and Trace Common Task

The checked common task joins GD-D18-S12 Yosys-style netlist structural
comparison and GD-D18-S08 supplied trace-difference projection as distinct
specialist jobs. Their fixtures are independent synthetic records, not proof
that a trace came from either design. The task preserves both original
requests and ownership assignments, requires R0 and empty resources, and
verifies the combined report against the separate original task.

This collaboration does not authenticate design provenance, correlate a
physical trace to a netlist, detect a hardware trojan, demonstrate a fault,
or grant live action authority or qualification.
