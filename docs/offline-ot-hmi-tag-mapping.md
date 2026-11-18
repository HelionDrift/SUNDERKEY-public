# Offline OT HMI Tag Mapping

This R0 component supports a narrow part of `AOE-GD-D19-S03`. It compares
caller-supplied baseline and HMI-project tag-to-point references and declared
access modes. A difference is only an unsigned declaration-difference candidate.
Each tag requires complete context, both point references, and both access
modes; missing values or incomplete inventory yield `unknown`.

The `read_only` and `read_write` labels describe supplied project metadata,
not effective permissions or actual point behavior. The component does not
query an HMI, SCADA system, historian, controller, network, or credential store.
It sends no commands and makes no claim about process behavior, impact, safety,
exploitability, finding status, or qualification. Replay verification requires
the separately retained original caller model.

The [synthetic example](../examples/offline-ot-hmi-tag-mapping-component.json)
contains fictitious tags and no target resources.
