# Supplied Source-Variant Tokens

The GE-D21-S17 component compares bounded, caller-supplied function IDs and
token sequences for two source snapshots. It reports added, removed,
unchanged, and modified function IDs. Modified functions receive an exact
longest-common-subsequence token count and a fixed-point similarity value.
Function and token order in the input inventory does not change the
classification.

The component does not read or parse source files, compile a program, or
test target behavior. Function matching and tokenization are supplied
assertions. Token similarity does not prove semantic equivalence or expose a
vulnerability. Incomplete inventories remain unknown. The output has no
finding, candidate, qualification, or execution authority.

The checked synthetic example is
[`examples/offline-source-variant-component.json`](../examples/offline-source-variant-component.json).
Verification requires replay against the original supplied model.
