# Supplied Wasm numeric stack and interfaces

This partial offline component inspects exact caller-supplied binary bytes. It
does not instantiate a module, execute instructions, resolve host imports, load
a runtime, or grant permission. A consistent selected observation is not proof
of full Wasm validity, host safety, an exploit, or qualification.

The semantics profile is
`wasm-w3c-wd-20220419-numeric-linear-subset.v1`. It deliberately pins the older
[April 2022 W3C Working Draft](https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/),
not a current full specification or a Recommendation. The document at that
dated URL identifies itself as a Working Draft; later specifications are not
silently adopted by this software profile.

## Input and public API

The exact closed model has three fields:

```json
{"schema_version":1,"source_id":"synthetic-numeric-wasm","module_base64":"..."}
```

`source_id` is a caller label, not authenticated provenance. `module_base64` is
canonical padded standard base64 containing the entire module. Native inputs
must use exact `dict`, `str`, and schema `int` families, not subclasses or
boolean/integer aliases. No file acquisition or external callback is built in.

The module exports:

- `analyze_supplied_wasm_numeric_stack(model)`.
- `analyze_supplied_wasm_numeric_stack_bytes(*, model_bytes)` for bounded ASCII
  JSON bytes, with duplicate keys and pre-decoder cost checks.
- `verify_supplied_wasm_numeric_stack_analysis(report, *, model)` for a complete
  comparison with a separately supplied original model.
- `WasmNumericStackAnalysis` and `WasmNumericStackError`.
- `component_fixture()`, a fresh hash-free public synthetic model.

Direct wrapper construction, `from_dict`, `from_json`, `to_dict`, and `to_json`
recompute the complete embedded original. Exported collections are detached.
Readdressing false stack, interface, source, offset, status, or effect fields
does not substitute for that replay. A coherently substituted embedded model
can only describe that different supplied model; separate-original verification
must still reject it. There is no freshness, source authority, replay guard,
same-process containment, or authorized-use assertion.

Reports retain all original module bytes in `source_model`, including custom
payloads. They are not sanitized for publication. `source_file_sha256` is SHA256
of the exact whole supplied bytes. Model and analysis identities use distinct
versioned domains; none is a signature or trusted origin.

The public fixture is a 70-byte synthetic module with two numeric types, two
legal duplicate-name function imports, one defined `i32 -> i32` function, and
one export of function index 2. Its five scanned instructions apply a declared
direct-call type and addition type, reaching a maximum operand stack of two;
no imported or defined function executes. Its literal analysis identity is
`WSA-D4337DA9B92BBAFA34E1F4278AAC2294`, with analysis digest
`sha256:d4337da9b92bbafa34e1f4278aac2294d34ad9392a1e9f5d648ed962cefceb5a`.

## Framing and interfaces

The selected binary grammar follows the pinned
[values](https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/values.html),
[types](https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/types.html), and
[modules](https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html)
rules. The magic and binary version one are exact. Section and known code-body
extents must close. Standard sections are unique and ordered as
`1,2,3,4,5,6,7,8,9,12,10,11`; custom section zero can appear anywhere. In
particular, data count precedes code even though its numeric identifier is 12.
Function and code vector counts must agree.

Unsigned and signed LEB accept legal nonminimal spellings within their declared
width. Terminal unused bits and maximum encoded byte counts are checked. Known
truncation, overrun, trailing contents, or malformed encodings are domain errors.
Names must be bounded valid UTF8. Their raw bytes are retained as base64 and
byte length, with no Unicode normalization. Duplicate import module/name pairs
remain legal. Exact decoded export names must differ; duplicates are known
adverse observations. Function import, declaration, export and direct-call
indices resolve only against supplied function types, not a host environment.

Supported signatures contain only `i32`, `i64`, `f32`, and `f64`, at most 64
parameters and at most one result. Known reference/vector types and up to 64
framed results can be retained, but are explicitly unassessed and do not acquire
a resolved numeric interface. Unknown type constructors and nonfunction
import/export descriptors are unsupported-subset refusals. That distinction
does not label every refused future feature globally invalid.

Recognized deferred table, memory, global, start, element, data-count and data
sections retain only their exact outer extents. Their omitted payload grammar,
counts, indices, initialization, and cross-section semantics are not validated.
Such a section always prevents a complete selected-subset consistency claim,
even when its payload resembles an empty vector. A custom section's valid name
is checked, while its remaining payload stays opaque.

## Straight-line type observations

The selected encodings and type transitions are grounded in the pinned
[instruction binary rules](https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/instructions.html),
[instruction validation](https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/valid/instructions.html),
and [module validation](https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/valid/modules.html).
Parameters precede expanded declared locals. The operand stack starts empty.

The supported straight-line instructions are `nop`, `drop`, `local.get`,
`local.set`, `local.tee`, the four constant families, each numeric family's
`add`/`sub`/`mul`, direct `call`, and a terminal `end`. Integer constants are
signed native integers. Float constants retain exact little-endian bit bytes,
including NaN payloads; no JSON floats or numeric execution occurs.

A direct call consumes declared parameter types and appends declared result
types without expanding its body. This holds for imported and recursive calls.
Terminal residual types must exactly match the supported declared result.
Known underflow, operand type, local/call/type/export index and result
contradictions are retained as adverse selected observations. After a known
stack contradiction, subsequent framing can be inspected without inventing a
replacement operand stack.

Unknown or deferred opcodes stop that body's scan immediately, before guessing
their immediates. No terminal stack conclusion is inferred from the unscanned
suffix. Structured control, unreachable polymorphism, select, indirect calls,
references, SIMD, memory and host semantics are not implemented. A prior known
contradiction remains adverse when a later feature is unassessed.

`selected_subset_status` is `consistent`, `adverse`, or `unassessed`, with known
contradictions dominating uncertainty. Function rows retain their selected
conclusion separately. Constant/direct-call/contradiction/unsupported-opcode
rows are the bounded semantic observation collection; `nop`, local and binary
instruction effects are summarized in counts and final type observations,
not an unbounded per-instruction trace.

## Finite cost contract

| Resource | Software ceiling |
| --- | ---: |
| Complete module | 256 KiB |
| Canonical model / report | 384 KiB / 2 MiB |
| Section rows | 256 |
| Types / imports / exports / defined functions | 128 each |
| Parameters / framed results per type | 64 / 64 |
| Supported results per type | 1 |
| Aggregate expanded locals, including parameters | 16,384 |
| Aggregate scanned instructions / operand stack | 65,536 / 4,096 |
| Retained semantic observations | 1,024 |
| One name / aggregate names | 128 bytes / 16 KiB |
| Scalar-inclusive depth | 16 |
| Model / report nodes | 4,096 / 262,144 |
| Cumulative whole public operation work | 128 MiB units |

These are software subset ceilings, not general Wasm bounds. Joint maxima need
not fit the byte, node or work caps. A refusal never silently truncates evidence.
Native collection queues, cycles, primitive types and signed64 magnitudes are
checked before cloning or hashing. Raw bytes, scalar-inclusive depth, node
queues, integer grammar, escapes and string lengths are bounded before JSON
decoding. Binary vectors, UTF8 decoding, expanded locals, operand pushes,
instruction scans and retained rows are funded before the corresponding
allocation or append.

Each of the eight public paths uses one cumulative budget: native analysis,
bytes analysis, direct construction, both reconstruction methods, both export
methods, and separate-original verification. Complete final source/report
retention, canonical encoding, equality, serialization and hash buffers are
reserved before the first SHA256. Separate-original verification funds both
complete plans in that same budget before either is hashed. No later work
reservation occurs after the first digest. Integrity computation is still not
source authentication, full validation, execution or host safety.

## Ownership and non-effects

This leaf is `wasm_supplied_numeric_stack_and_interfaces`, with existing profile
`AOE-GE-D21-S19`, capability `army.ge.d21.s19`, vector `AV-GE-D21-S19-01`, package
`IWP2-AOE-GE-D21-S19`, wave `IW2-001`, commander `AOE-GE-D21-CMD`, group owner
`AOE-HQ-07` and independent validator `AOE-HQ-19`. Its blueprint is
`sha256:5d56faef4e97aed134752503f33bf183368ef7c4d19189bcb1d69b524acc962d`.

Only partial A7.4 supplied-model evidence is added. All authority, conformance,
execution, safety, qualification and positive-use flags remain false. Every
effect is `none`. Original D016 decisions, live gates, six reference SDKs,
routing, deployment and independent qualification are unchanged. There is no
Wasm engine, runtime installation, filesystem acquisition, provider callback,
network request, credential handling or target execution.
