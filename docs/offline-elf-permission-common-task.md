# Supplied ELF Layout and Section-Permission Common Task

The checked common task joins the existing GB-D08-S17 ELF64 layout
specialist and the GE-D21-S02 AArch64 section-permission specialist on
one synthetic, read-only task. Each job retains its original request,
profile, commander, and source-bound component result. The task requires
R0, no resources, and no credentials before dispatch. It rejects a
late resource grant or a nonsynthetic policy model before either job
runs.

The two reports are complementary, not independent evidence of runtime
behavior. The layout analyzer checks a bounded file format subset. The
policy projection compares supplied section declarations with a supplied
policy. Neither performs target interaction, loader execution, or
qualification.
