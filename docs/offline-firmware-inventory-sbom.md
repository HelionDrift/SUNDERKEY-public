# Offline Firmware Inventory and SBOM Claim Reconciliation

This R0 partial component for `AOE-GD-D18-S01` compares two caller-supplied sets of normalized component claims: a firmware inventory and an SBOM inventory. It matches exact component IDs, versions and declared SHA-256 strings. Missing or differing claims become unsigned review candidates only when the caller declares both sets complete. Otherwise the disposition is unknown. Rows remain visible for review but do not count as candidates with incomplete input.

This is claim reconciliation, not firmware acquisition, unpacking or SBOM parsing. It never opens firmware or SBOM files, decompresses content, reads component bytes, calculates a component digest, contacts a device or network, or verifies provenance. Equality of supplied digest strings does not establish that firmware contains the claimed bytes. Neither a mismatch nor a match is a finding, a qualification result or permission for positive use.

The model accepts at most 128 entries in each set, requires native JSON fields, rejects duplicate component IDs within each set, and produces a deterministic, content-addressed report. The report can be verified only by replay against a separately retained original model. `inventory_source_id` and `sbom_source_id` are caller-provided identifiers, not authenticated provenance.

Example: [`examples/offline-firmware-inventory-sbom-component.json`](../examples/offline-firmware-inventory-sbom-component.json).
