# Offline OT Controller Configuration

This R0 component supports a narrow part of `AOE-GD-D19-S02`. It compares
caller-supplied baseline and project-export SHA-256 labels for controller logic
and I/O maps. A mismatch is only an unsigned declaration-difference candidate.
Each controller requires complete context and all four digests; a missing digest
or incomplete inventory yields `unknown`, not a candidate.

The component does not acquire firmware, inspect a deployed controller, execute
logic, send PLC/RTU/PAC commands, access credentials, or interact with a network
or physical process. It establishes neither deployed configuration nor process
behavior, impact, safety, exploitability, finding status, or qualification.
Replay verification requires the separately retained original caller model.

The [synthetic example](../examples/offline-ot-controller-configuration-component.json)
uses fictitious digest labels and no target resources.
