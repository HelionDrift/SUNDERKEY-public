# Supplied Linux Module Information Tags

The GE-D21-S04 partial component replays the bounded
[ELF64 layout analyzer](offline-elf64-layout-analysis.md) over original,
synthetic bytes. It reads a bounded `.modinfo` section and reports tag
presence and counts, not tag values. The checked example is
[`examples/offline-linux-module-info-component.json`](../examples/offline-linux-module-info-component.json).

Linux's [`MODULE_INFO` macro](https://github.com/torvalds/linux/blob/master/include/linux/moduleparam.h)
emits `tag=value` records in `.modinfo`. This projection requires a supplied
ELF64 section-name string table and rejects malformed, oversized, or
unterminated records. It does not authenticate the supplied bytes, verify a
signature or kernel compatibility, load a module, establish exploitability,
or qualify an agent. No binary is acquired, executed, or sent to a target.
Independent verification replays the separate original model.
