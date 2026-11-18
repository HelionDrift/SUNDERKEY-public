# Supplied ELF64 layout analysis

This R0 component examines explicitly supplied, inert file bytes. It does not
acquire a host file, load a binary, resolve imports, execute instructions or
interact with a target. A successful report is an unsigned statement about the
supported geometry subset, not a full ELF validity or exploitation verdict.

## Existing ownership

The component ID is `linux_supplied_elf64_layout`. It belongs to the existing
`AOE-GB-D08-S17` Linux native binary specialist, capability `army.gb.d08.s17`,
vector `AV-GB-D08-S17-01`, package `IWP2-AOE-GB-D08-S17`, wave `IW2-003` and
commander `AOE-GB-D08-CMD`. Group ownership stays with `AOE-HQ-04`; independent
validation stays with `AOE-HQ-19`. No profile, authority, qualification or
deployment state is created or promoted.

## Closed supplied model

The exact three fields are:

```json
{
  "schema_version": 1,
  "source_id": "synthetic-elf64",
  "elf_file_base64": "<canonical padded base64 supplied by the caller>"
}
```

The schema value must be the exact native integer `1`. Source IDs are printable
ASCII, at most 64 characters, starting with a letter or digit and otherwise
using letters, digits, period, underscore, colon or hyphen. Fields are closed.
The source label is not proof of an acquisition, host identity or provenance.
Bytes are retained in the report and are not sanitized for confidentiality.

`component_fixture()` returns a fresh synthetic 316-byte container containing
one declared load segment, an ordinary file-backed section, a no-file-content
section and inert `DATA` bytes. The declared entry address does not authorize
or cause execution.

## Selected interpretation

The source profile is the [generic ELF header specification](https://gabi.xinuos.com/elf/02-eheader.html),
[section specification](https://gabi.xinuos.com/elf/03-sheader.html) and
[program header specification](https://gabi.xinuos.com/elf/07-pheader.html),
reviewed as the ELF 4.3 draft on 2026-09-29. This is a named documentation
snapshot, not a cryptographically pinned upstream publication or ABI guarantee.

The parser accepts version-one little-endian ELF64, the standard 64-byte header,
56-byte program records and 64-byte section records with bounded ordinary
counts. Extended numbering is refused as outside this subset. The first section
record must be all zero in this ordinary-count profile.

Nonempty header tables must fit the supplied bytes and be disjoint from each
other and the ELF header. Unknown ABI metadata, header flags, file types,
program types and section attributes remain visible and unassessed.

For declared EXEC and DYN types, `PT_LOAD` checks file size against memory size,
checked address ends, ascending virtual addresses and declared alignment
congruence. Segment overlaps are not rejected solely for sharing bytes. No
memory mapping, page size or runtime protection is established.

File-backed section ranges must fit, avoid header tables and not overlap each
other. Section alignment checks addresses, not file offsets. `SHT_NOBITS`
has no supplied file extent; its conceptual offset is not treated as a file
read. Undefined fields of `PT_NULL` and noninitial inactive sections remain
raw observations rather than interpreted ranges.

All uint64 fields and derived ends use fixed-width hexadecimal text. Interval
overflow is a refusal of this arithmetic profile, not a universal loader
compatibility assertion. Names, string table content, symbols, relocation
contents, compressed data, entry points and dynamic linking are not resolved.
The report does not assert that allocated sections are covered by load mappings.

## Public API and separate-original replay

The module is `sunderkey.offline_elf64_layout_analysis`.

- `analyze_supplied_elf64_layout(model)` accepts an exact native model.
- `analyze_supplied_elf64_layout_bytes(model_bytes=...)` accepts exact ASCII JSON bytes.
- `Elf64LayoutAnalysis`, `from_dict` and `from_json` replay the complete embedded source.
- `to_dict` and `to_json` revalidate complete canonical report content.
- `verify_supplied_elf64_layout_analysis(report, model=original)` additionally
  requires equality with a separately supplied original model.

The `ELA-` identity binds the complete analysis body. Separate source-model and
file-byte SHA-256 values are included. These addresses protect deterministic
content consistency, not trust in the caller or a signature. Rehashing altered
observations, omitted rows or promoted flags cannot replace full source replay.
A coherent different source is still rejected against the original source.

Native intake rejects aliases, custom mapping families, cycles, floats, invalid
depth and excessive queued nodes before copying. Raw intake rejects duplicate
keys, noninteger numeric forms and excessive lexical structure. Exports are
detached, while the wrapper is frozen. Expected refusal uses
`Elf64LayoutAnalysisError`; no programming exception is converted into success.

## Software limits and complete-pass accounting

Limits are 524,288 supplied file bytes, 1,048,576 canonical model bytes,
2,097,152 canonical report bytes, 16,384 model nodes, 262,144 report nodes,
native depth 16, 128 program records and 1,024 section records. These are
software ceilings, not promises that every simultaneous maximum can fit.

One cumulative budget of 134,217,728 work units covers a complete public pass.
Intake, retention reservations, parsing, encoding, copies, equality and digest
buffers are funded before the first digest. Separate-original verification
funds both derivations before hashing either. Exact-budget and one-below
controls cover all eight public forms. No network or process resource grant
is issued by this accounting.

## Evidence boundary

This is partial evidence for `A7.4`, not an assembled or qualified specialist.
All source authentication, loader, execution, vulnerability, positive-use and
qualification flags are false. All file acquisition, host, network, credential,
provider, process, execution, authority, qualification and deployment effects
are `none`. Future live use still requires the repository's separate current
authorization, custody, infrastructure and independent acceptance gates.
