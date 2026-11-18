# Supplied AMD64 PE Section-Permission Policy

The GE-D21-S01 partial component replays the repository's bounded
[PE32+ layout analyzer](offline-pe32-layout-analysis.md) over original
synthetic PE bytes, then compares section write and execute flags with a
separately supplied policy. The checked example is
[`examples/offline-pe-section-permissions-component.json`](../examples/offline-pe-section-permissions-component.json).
The flag masks follow the [Microsoft PE format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format):
`IMAGE_SCN_MEM_EXECUTE` is `0x20000000` and `IMAGE_SCN_MEM_WRITE` is
`0x80000000`. A W+X section is flagged only when the supplied policy forbids
it. This is a static declaration comparison, not a normative PE rejection.

The component retains only the base analysis and source digests in its
report. Independent verification replays the separate original model and
base parser. Unsupported machine or uncertain base layout stays unknown.
No binary is acquired, loaded, or executed. The flag comparison does not
establish runtime permissions, exploitability, vulnerability impact, or a
qualified candidate.
