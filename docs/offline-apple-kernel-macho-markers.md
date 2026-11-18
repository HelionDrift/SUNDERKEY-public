# Supplied Apple Kernel Mach-O Header Markers

The GE-D21-S05 partial component replays the bounded
[Mach-O64 layout analyzer](offline-macho-analysis.md) over original,
synthetic bytes. It projects the file-type, CPU, UUID, and code-signature
load-command markers against a supplied requirement list. The checked
example is
[`examples/offline-apple-kernel-macho-markers-component.json`](../examples/offline-apple-kernel-macho-markers-component.json).

The marker values follow Apple's
[`mach-o/loader.h`](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h):
`MH_KEXT_BUNDLE` is `0xb`, `MH_FILESET` is `0xc`, and
`LC_CODE_SIGNATURE` is `0x1d`. The component checks whether the
declared signature blob lies within the supplied byte array. It does not
parse or verify that signature. The base analyzer leaves kext and fileset
loader semantics unassessed, and this projection preserves that status.

No kernel artifact identity, loadability, runtime behavior, exploitability,
finding, or agent qualification is established. No binary is acquired,
executed, or sent to a target. Independent verification replays the
separate original model.
