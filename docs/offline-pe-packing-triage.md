# Supplied PE Packing Triage

The GE-D21-S20 partial component measures byte distributions in raw PE32+
sections and reports trailing-file geometry from a bounded synthetic file.
The [Microsoft PE format reference](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
defines section `SizeOfRawData` and `PointerToRawData` and describes attribute
certificate table placement. The implementation reuses SUNDERKEY's existing
PE layout parser, then computes a SHA-256 digest and integer-scaled Shannon
entropy for each materialized raw section. The checked example is
[`examples/offline-pe-packing-triage-component.json`](../examples/offline-pe-packing-triage-component.json).

Entropy and trailing bytes are descriptive, not malware or packing indicators
by themselves. This component does not unpack code, extract configuration,
interpret behavior, verify signing, or identify a packer. It accepts only
synthetic supplied bytes and replays against a separate original model.
No file is loaded or executed, no target is contacted, and no finding or
qualification is produced.
