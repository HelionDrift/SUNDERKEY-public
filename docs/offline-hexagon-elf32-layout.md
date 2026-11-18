# Supplied Hexagon ELF32 Program Geometry

The GE-D21-S06 partial component checks a bounded, synthetic, little-endian
ELF32 header and program-header table. It reports segment extents, declared
memory sizes, flags, alignment, and the Hexagon machine marker. The checked
example is
[`examples/offline-hexagon-elf32-layout-component.json`](../examples/offline-hexagon-elf32-layout-component.json).

The header and segment fields follow the [ELF header](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch4.eheader.html)
and [program-header](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch5.pheader.html)
specifications. [LLVM's ELF constants](https://www.llvm.org/docs/doxygen/BinaryFormat_2ELF_8h.html)
identify `EM_HEXAGON` as `164`. This is a static format marker, not proof
that the bytes came from a baseband or DSP, that they can load, or that
their instructions are valid.

Sections, relocations, signatures, processor-specific flags, loaders, and
runtime behavior remain unassessed. No firmware is acquired, loaded,
executed, or sent to a target. No finding or qualification is produced.
Independent verification replays the separate original model.
