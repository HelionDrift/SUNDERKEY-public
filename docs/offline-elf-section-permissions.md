# Supplied AArch64 ELF Section-Permission Policy

The GE-D21-S02 partial component replays the bounded
[ELF64 layout analyzer](offline-elf64-layout-analysis.md) over original,
synthetic ELF bytes, then compares allocated section write and execute
flags with a separately supplied W+X policy. The checked example is
[`examples/offline-elf-section-permissions-component.json`](../examples/offline-elf-section-permissions-component.json).

The [ELF generic ABI](https://refspecs.linuxfoundation.org/elf/gabi4%2B/ch4.sheader.html)
defines `SHF_WRITE` as `0x1`, `SHF_ALLOC` as `0x2`, and `SHF_EXECINSTR`
as `0x4`. The
[Arm AArch64 ELF ABI](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst)
identifies `EM_AARCH64` as machine 183. An allocated W+X section is
flagged only when the supplied policy forbids it. This is a static flag
comparison, not a loader or runtime permission test.

The report retains the base analysis and source digests, not executable
bytes. Independent verification replays the separate original model
through the base parser. Unsupported machine or uncertain base layout
stays unknown. No binary is acquired, loaded, or executed. A flagged
section does not establish exploitability, vulnerability impact, or a
qualified candidate.
