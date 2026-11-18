# Supplied thin Mach-O64 layout subset

This partial offline component performs actual byte parsing and checked layout
arithmetic on a caller-supplied file. It does not inspect an iOS device, unpack an
IPA, load code or certify Mach-O validity, signatures, installation or vulnerabilities.

## Existing ownership

Component `ios_supplied_macho64_layout` belongs to profile `AOE-GB-D08-S05`,
capability `army.gb.d08.s05`, vector `AV-GB-D08-S05-01`, package
`IWP2-AOE-GB-D08-S05` and wave `IW2-009`. Its commander is `AOE-GB-D08-CMD`,
group owner `AOE-HQ-04`, and independent validator `AOE-HQ-19`. The unchanged
blueprint binding is
`sha256:5390c215a247ebe2692e62bf9cf63554271141e778580f51afa7f61d9ef4397d`.
Initial roadmap evidence is A7.4 only. Candidate, package, qualification and
deployment states are not promoted by this partial algorithm.

## Exact model and public API

```json
{
  "schema_version": 1,
  "source_id": "declared-local-file",
  "macho_file_base64": "canonical-padded-standard-base64"
}
```

The three fields are closed. Schema version is exact native integer one;
`source_id` is a bounded unsigned ASCII label, not origin authentication.
Base64 has no whitespace, uses the standard alphabet and required padding,
and must have canonical padding bits. Decoded length is checked before decoding.

- `analyze_supplied_macho_layout(model) -> MachOAnalysis`
- `analyze_supplied_macho_layout_bytes(*, model_bytes) -> MachOAnalysis`
- `verify_supplied_macho_layout_analysis(report, *, model) -> MachOAnalysis`
- `component_fixture() -> dict` returns fresh wholly synthetic metadata.

The bytes entry point accepts bounded native ASCII JSON bytes. Equivalent
JSON whitespace and ASCII escapes preserve canonical model identity; duplicate
keys at every depth are rejected. The result is an exact frozen `MachOAnalysis`.
Its constructor, `from_dict`, `from_json`, `to_dict` and `to_json` replay the
complete embedded file and source model. Report JSON must be exact canonical
ASCII-escaped JSON. Malformed wrappers, incomplete slots, native aliases and
coherently rehashed false observations cannot pass that replay.

Embedded replay is unsigned content consistency, not source authentication.
A coherent alternative file can produce its own valid report. The verifier
therefore also requires a separately supplied original model and compares exact
reconstructions. Returned dictionaries and source models are detached. These
local ownership checks do not sandbox arbitrary Python memory mutation or
authenticate a file acquired elsewhere.

## Primary semantics and checked subset

The independently written parser follows the relevant structures and comments
in Apple's official
[loader.h at e6231be02a03711ca404e5121a151b24afbff733](https://github.com/apple-oss-distributions/xnu/blob/e6231be02a03711ca404e5121a151b24afbff733/EXTERNAL_HEADERS/mach-o/loader.h).
No upstream parser code is included and no platform API is called.

The supported container is thin little-endian Mach-O64 with a 32-byte header.
The magic is exact; CPU fields, header flags and reserved words are retained
without pretending to validate their machine-specific meaning. The declared
command block must fit the supplied bytes. Each command has its eight-byte
prefix, an eight-aligned size and an exact next offset. Command count and the
sum of actual command sizes must consume the complete declared block.

`LC_SEGMENT_64` has exact fixed geometry: 72 bytes plus 80 bytes per section.
Declared counts are bounded before record expansion. Known intervals use checked
addition; interval ends must fit uint64 in this narrow arithmetic profile.
This refusal is not a statement about every possible Mach-O file. Alignment
exponents above 63 are a local supported-profile limit, checked before shifting.
Unsigned64 fields and ends are fixed-width `0x` plus sixteen lowercase hex digits,
not coerced into signed JSON integers. Names retain all sixteen bytes as
32-character hex, including embedded NULs, nontext octets and trailing bytes.

Nonempty segment file extents must fit the supplied file. For flags-zero
`MH_OBJECT` or `MH_EXECUTE`, file size cannot exceed VM size. Nonempty regular
sections have checked file ranges, alignment and containment in their declared
segment file/VM extents, and cannot occupy header or command bytes. Known
zero-fill sections have VM containment but **no inferred file extent**. Their
offset field is retained without requiring it to address file data. Empty
sections/segments do not acquire content ranges merely from an offset.
Known regular sections cannot follow a known zero-fill section in this profile.

An ordinary object file's file-backed segment does not include its header and
commands. An executable file-backed segment may legitimately contain them;
the observation `contains_header_and_commands` is not a universal overlap
error. Object sections can declare their own segment names while the enclosing
segment is unnamed. Exact name equality is observed, not enforced or normalized.
This is not an all-segment overlap, address-space or loader-mapping verifier.

`LC_UUID` is supported only as its fixed 24-byte structure and sixteen raw UUID
bytes. Repetition does not prove or disprove global uniqueness; neither the UUID
nor a file hash authenticates the producer or platform.

Other commands, including code-signature/encryption commands and unknown
required-dyld commands, retain `unassessed_command`. Unknown section types have
no invented file extent. Section attributes and every nonzero segment flag
are unassessed. In particular, `SG_HIGHVM` does not accidentally use the ordinary
file-to-VM interpretation. Other file types retain parsed records but withhold
the known object/executable geometry interpretation. Any such condition yields
`layout_semantics_unassessed`, not a clean loader or safety result.

Relocation offsets/counts, protections, symbol tables, entry points, fixups,
machine instructions and payloads of unknown commands are not validated.
Structural contradictions and software exhaustion raise `MachOAnalysisError`;
neither is reported as a vulnerability or a negative security finding.

## Exact replay, metadata and software ceilings

The report embeds the unsanitized original base64 model, exact decoded-file
SHA256, separately domain-bound canonical model SHA256, header, ordered commands
and segment/section observations. Domains are `sunderkey.offline-macho-model.v1`
and `sunderkey.offline-macho-analysis.v1`; report identities use `MCA-`.
All source-authentication, loader/signature/runtime/security/qualification flags
are false. All effects are `none`. No output is extracted, rendered, executed,
converted into a finding or used to grant admission or target access.

| Local software ceiling | Limit |
| --- | ---: |
| Decoded file / canonical model / report bytes | 512 KiB / 1 MiB / 2 MiB |
| Model / report native nodes | 16,384 / 262,144 |
| Native and raw scalar-inclusive depth | 16 |
| Commands / segments / aggregate sections | 256 / 64 / 1,024 |
| Alignment exponent | 63 |
| Cumulative work per complete public operation | 134,217,728 units |

Native families, cycles, repeated subtrees, queued children and ASCII escape
costs are bounded before copying. Raw integer grammar, scalar/container depth,
nodes and strings are checked before JSON decoding. Signed64 JSON integers
use explicit lexical bounds before conversion. Binary record counts/ranges
are checked before expansion. Conservative fixed reservations of 512 bytes/40
nodes per command, 1,024/60 per segment and 1,536/64 per section fund retained
rows before allocation/appending. These are local cost reservations, not exact
format sizes or authority limits. Final full-report measurement also applies.

All identities reserve their complete fixed widths. Source/file hashing,
canonical buffers, reconstruction, export, equality and separately-original
verification are cumulatively funded before **any digest** in each public pass.
Work exhaustion late in planning therefore cannot run an earlier source digest.
Individual maximum declarations need not fit simultaneous retained-output or
complete replay costs. These limits do not promise OS memory isolation or
concurrent caller-memory stability.

## Synthetic proof scope

Tests manually encode little-endian fields independently of the parser. They
cover real object and executable geometry, zero-fill/empty ranges, unsigned64
text, raw names, unknown mappings and fixed-count boundaries. A small interval
oracle enumerates covered byte/address positions rather than copying endpoint
predicates. Full source substitutions, false cohashed rows, native/raw aliases,
canonical replay, detachment and each public operation's exact work boundary
are tested without device, provider, credential, external-process or platform-loader
access.

The public fixture is a 188-byte synthetic object with one unnamed segment,
one four-byte regular section and literal inert `DATA` bytes. Its report does
not assert that this deliberately small object is linkable or installable.
The independently encoded literal control is
`MCA-B483D07354A521FE0B2D95415A832051`, report digest
`sha256:b483d07354a521fe0b2d95415a832051b829859a054df519838f923f0b31486a`,
model digest
`sha256:031a34c99aff789d8c46cd0ddf0a8b7fb0914557baa1cb29d6bbfc1fa5b9016d`
and file digest
`sha256:c4a9316bf97b6f99c4e311875423fb9f30e9d2b856bfb0a6fc443398830badbc`.
The canonical model/report lengths are 327/5,090 bytes. These identities are
unsigned synthetic content controls, not iOS authenticity evidence.
