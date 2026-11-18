# Supplied PE32+ layout analysis

This additive component computes bounded header and declared-extent predicates over caller-supplied bytes. It does not load a file or establish that an image is a valid, authentic, executable or safe Windows program. The input and result are unsigned. Every effect is `none`; every authentication, loading, execution, positive-use and qualification flag is false.

## Existing ownership

The component is `windows_supplied_pe32plus_layout`, under profile `AOE-GB-D08-S15`, capability `army.gb.d08.s15`, vector `AV-GB-D08-S15-01`, package `IWP2-AOE-GB-D08-S15` and wave `IW2-001`. Commander `AOE-GB-D08-CMD` belongs to `AOE-HQ-04`; independent validation belongs to `AOE-HQ-19`. Its original blueprint is `sha256:e17edd936887b65ab10f39ee99a24783d1d68c4f97ec2258b1d43a11e1a6c21c`. It supplies only partial A7.4 evidence. It does not alter the original six SDKs, D016 records, qualification gates or routing.

## Source and public API

The closed model has exactly three fields:

```json
{"schema_version":1,"source_id":"synthetic-pe32plus","pe_file_base64":"..."}
```

`schema_version` is native integer 1, not a boolean or float. `source_id` is a printable ASCII identifier of at most 64 characters from the documented identifier alphabet. `pe_file_base64` is canonical padded standard base64 encoding of the complete supplied file. The component reads no filesystem, OS, process, registry, credential or network port.

```python
analyze_supplied_pe32plus_layout(model)
analyze_supplied_pe32plus_layout_bytes(model_bytes=exact_native_bytes)
verify_supplied_pe32plus_layout_analysis(report, model=separate_original_model)
Pe32PlusLayoutAnalysis(document_json)
Pe32PlusLayoutAnalysis.from_dict(document)
Pe32PlusLayoutAnalysis.from_json(document_json)
report.to_dict()
report.to_json()
```

The bytes entry point permits bounded whitespace and equivalent ASCII JSON escapes; duplicate fields are rejected. Retained report text must be exact canonical ASCII JSON. Exports return detached data. Construction, parsing and export all rederive the observations from the complete embedded source. The separate-original verifier also compares the full report rederived from the independently supplied model. A coherently different embedded source is not made authentic by its hashes, and cannot replay against another original.

`source_file_sha256` hashes every exact supplied byte, including header padding, raw padding, opaque certificates and overlays. It is not the Authenticode image hash. The separate model domain is `sunderkey.offline-pe32plus-model.v1`; the report domain is `sunderkey.offline-pe32plus-layout-analysis.v1`, with `PLA-` identities. Complete source base64 is retained. Reports are not sanitized and must not be assumed safe to publish.

## Finite geometry profile

The engineering subset follows Microsoft's primary [PE Format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format), personally reviewed for the DOS/PE/COFF headers, PE32+ optional header, section table/data and attribute certificate envelopes. It is a partial supplied-byte interpretation, not complete specification conformance or empirical loader behavior.

The parser checks `MZ`, the declared `e_lfanew`, `PE\0\0`, the complete 20-byte COFF header, PE32+ magic `0x20b`, the declared optional-header extent and its advertised directory count. Section-table placement derives from `SizeOfOptionalHeader`, not a fixed sixteen-directory assumption. Other optional-header formats are refused as outside this software subset. Raw integer metadata is retained without inferring timestamp truth, mitigation enforcement or executable entry-point correctness.

AMD64 (`0x8664`) uses a deliberately named profile. The PE header is eight-byte aligned; ImageBase is 64-KiB aligned. File and section alignments are powers of two. The 4096 boundary is an explicit profile parameter, not a universal page size or an observation of a host. At or above that boundary, file alignment is 512 through 65536 and cannot exceed section alignment. Below it, both declared alignments must be equal and nonempty section raw offsets must equal their RVAs. Headers cover the aligned table; the declared image size is section aligned and at most `0x80000000`. Unknown machines remain unassessed and do not inherit these AMD64 alignment or RVA-to-file predicates.

Nonempty raw extents must fit the supplied bytes and not overlap headers or each other. The supported AMD64 profile also requires nonempty raw section data to preserve section-header/RVA order. Logical sections have ascending, adjacent section-aligned RVAs in this subset, beginning after aligned headers. This is a declared layout check, not a blanket assertion about what every loader accepts. Logical `VirtualSize` and raw `SizeOfRawData` remain separate. Raw padding is not substituted for a logical range; zero-filled tails are not invented file bytes. Zero `VirtualSize` is explicitly unassessed with no loader fallback. A zero raw size creates no file extent, even if its unused raw pointer is large.

Directory pairs `(0,0)` are retained as declared absent. Partial pairs, reserved or extended entries and unsupported mappings stay unassessed. Ordinary nonempty directory RVAs must fit the declared image. A unique mapping is reported only within headers or one logical section and its supplied raw backing; crossing a section, raw padding or zero fill does not manufacture a backing pointer. Directory payloads, imports, symbols, relocations, debug formats and entry-point semantics are not parsed or resolved. Unknown flag bits, unsupported subsystems and reserved/extended metadata do not silently become clean claims.

The certificate directory is the special file-offset entry, not an RVA. Its supplied file extent is checked separately from image RVAs, is eight-byte aligned, and does not overlap headers or section data. The walk reads only each eight-byte `WIN_CERTIFICATE` envelope, retaining `dwLength`, revision and type. Rounded eight-byte occupancy must exactly fill the advertised directory size. Payload and padding stay opaque: the software does not infer a precise certificate-content length from padding, validate its zeros, require unique certificates, parse CMS/DER, verify signatures or authenticate a signer. Unknown revisions/types stay unassessed. Trailing supplied bytes are retained as opaque overlay/debug observations, not loaded data.

## Refusal versus unassessed

`Pe32PlusLayoutAnalysisError` denotes a closed/native input violation, unsupported format intake, software ceiling, exact replay mismatch or contradiction in a predicate the selected subset actually checks. This is not a universal malformed-PE finding. `layout_semantics_unassessed` retains unsupported metadata and explains why the named subset cannot make a complete positive conclusion. `supported_layout_subset_consistent` means only the implemented supplied geometry predicates are consistent. It never means full PE validity, host compatibility, executable authenticity or permission to run.

The model does not validate the DOS program, executable code, import resolution, relocation contents, checksum, Authenticode, directory bodies, certificate truth, runtime mitigations, signing authority, exploitability or vulnerability. There are no file-acquisition, process, installation, target, provider or credential callbacks.

## Software costs and tests

Ceilings are 512 KiB decoded file, 1 MiB canonical model, 2 MiB canonical report, 96 section headers, 32 directories and 64 certificate envelopes. Exact native integer-only JSON has scalar-inclusive depth 16, 16384 model nodes and 262144 report nodes. Booleans occur only where the exact derived report expects them. Public integer metadata is signed64; binary uint64 fields are retained as fixed-width hexadecimal strings, not lossy signed coercions. Repeated subtrees are charged, cycles and foreign container/scalar families are denied before copying. Raw lexical byte, node, depth, string, escape and integer limits precede JSON decoding.

One cumulative work counter per public operation has a 134217728-unit ceiling. Source capture and canonical base64 work, bounded header/table walks, retained row reservations, complete result materialization, encoding, hashing and equality passes share it. Every complete native/bytes producer, wrapper constructor, from-dict/from-JSON reconstruction, export and separate-original verification funds its remaining work before its first digest. The ordinary operations use three digests; separate-original replay uses six, after both complete plans have been funded. Bounds are local software controls, not global lifetime, OS containment or denial-of-service certification.

Tests use independently encoded synthetic header/data bytes, never operational executables. They cover literal source/model/report goldens, low and ordinary alignment, logical-versus-raw extents, section ordering, typed directory backing, rounded opaque certificate envelopes, unknown-machine withholding, complete source changes, coherent false report readdressing, detached exports and separate-original denial. A small independent grid checks exact one-byte logical/raw mapping predicates. Exact work thresholds and threshold-minus-one refusal are checked at all eight public forms before any hash. `component_fixture()` returns a fresh inert synthetic model without import-time generation or execution.
