# Offline ACPI Table Integrity

This R0 component supplies a narrow, bounded part of `AOE-GD-D24-S01`. It reads caller-provided byte values for one ACPI table and compares the common header's declared length with the supplied length. For a complete table of at least 36 bytes, it also checks the whole-table 8-bit checksum. The [UEFI ACPI specification](https://uefi.org/specs/ACPI/6.6/21_ACPI_Data_Tables.html) defines the common header, length and checksum fields for these tables. FACS is excluded.

A result is only a candidate about supplied bytes. The source and completeness flag are unauthenticated. FACS is explicitly unsupported and produces an unknown result rather than a common-header candidate. Table-specific bodies, AML, firmware identity and exploitability are not evaluated. No firmware or platform interface is read.

The unsigned report requires separately retained original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-acpi-table-integrity-component.json`](../examples/offline-acpi-table-integrity-component.json).
