# Supplied Windows Driver PE Header Markers

The GE-D21-S03 partial component replays the bounded
[PE32+ layout analyzer](offline-pe32-layout-analysis.md) over original,
synthetic bytes and projects selected header markers against a supplied
required-marker list. The checked example is
[`examples/offline-windows-driver-pe-markers-component.json`](../examples/offline-windows-driver-pe-markers-component.json).

The marker values follow the
[Microsoft PE format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format):
native subsystem `1`, COFF system-file bit `0x1000`, WDM-driver DLL bit
`0x2000`, dynamic-base bit `0x0040`, NX-compatible bit `0x0100`, and
force-integrity bit `0x0080`. Native subsystem can identify a driver
or a native process; no combination here proves driver identity.

The base analyzer leaves native subsystem semantics outside its named
layout subset, so this component preserves that uncertainty even when
all supplied markers appear. It does not validate a signature, load a
driver, measure kernel mitigations, establish exploitability, or
qualify an agent. No binary is acquired, executed, or sent to a target.
Independent verification replays the separate original model.
