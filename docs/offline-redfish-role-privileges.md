# Offline Redfish Role Privileges

This R0 component supplies a narrow part of `AOE-GD-D24-S02`. It compares caller-provided account role references with supplied Redfish role `AssignedPrivileges` and account-specific permitted privilege ceilings. A missing role or an assigned privilege outside a supplied ceiling is a review candidate when the inventory is declared complete. The [DMTF Redfish specification](https://redfish.dmtf.org/schemas/DSP0266_1.20.1.html) describes role privilege assignments.

The declarations do not establish BMC state, actual account grants, OEM privilege semantics or effective access. No BMC, IPMI or Redfish endpoint is contacted. The account ceiling is a caller-provided policy, not an inferred standard requirement.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-redfish-role-privileges-component.json`](../examples/offline-redfish-role-privileges-component.json).
