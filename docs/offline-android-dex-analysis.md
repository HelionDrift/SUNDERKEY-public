# Supplied Android DEX035 structure subset

This partial offline component checks supplied unlinked little-endian DEX035
bytes. It performs actual header, map, range and referenced-string parsing,
not a device operation or an APK authentication test. It does not validate
bytecode, classes, names, installation, vulnerabilities or specialist qualification.

## Existing ownership

The component is `android_supplied_dex035_structure`, profile `AOE-GB-D08-S01`,
capability `army.gb.d08.s01`, vector `AV-GB-D08-S01-01`, package
`IWP2-AOE-GB-D08-S01`, wave `IW2-005`. The commander is `AOE-GB-D08-CMD`,
group owner `AOE-HQ-04` and independent validator `AOE-HQ-19`. The original
blueprint digest is
`sha256:ac670888f02a931e64507b0ad52d933ae6091e81ebc166b0ddec02b51fed04c2`.
No original candidate, package, status, signed domain or qualification gate is changed.

## Exact supplied model and API

`analyze_supplied_android_dex(model)` accepts an exact native JSON object:

```json
{
  "schema_version": 1,
  "source_id": "declared-local-file",
  "dex_file_base64": "canonical-padded-base64-of-the-supplied-file"
}
```

`source_id` is an unsigned bounded ASCII label, not origin authentication.
Base64 must use the standard alphabet, required padding and canonical padding
bits, with no whitespace. Declared decoded length is bounded before decoding.
`analyze_supplied_android_dex_bytes(*, model_bytes)` accepts bounded native
ASCII JSON bytes. Equivalent raw JSON whitespace and ASCII escapes preserve
canonical model identity, but duplicate keys at any depth are rejected.

The result is a frozen `AndroidDexAnalysis`. Its `from_dict`, `from_json`,
direct constructor, `to_dict` and `to_json` replay all embedded source bytes.
Report JSON must be exact canonical ASCII-escaped JSON. The public
`verify_supplied_android_dex_analysis(report, *, model)` additionally requires
the separately supplied original model. Content replay alone cannot establish
that a coherent alternate source was the caller's original. Returned metadata
and `component_fixture()` are detached; the fixture is wholly synthetic.

## What is checked

The implementation is independently written from the primary
[AOSP DEX format description](https://source.android.com/docs/core/runtime/dex-format),
specifically its older-version header, layout, map, LEB128 and MUTF-8 rules.
The supported profile is DEX035 only, not newer containers or compact DEX.

The 112-byte header must declare the exact supplied file size, little-endian
tag, no link section and a final aligned data extent. Empty fixed arrays have
zero offsets; nonempty arrays have ordered, nonoverlapping aligned ranges.
Type/prototype count bounds and a narrower string-count ceiling are checked.
Fixed table contents are not validated as types, prototypes, fields, methods
or classes.

The map must contain its header, self-entry and every nonempty fixed section
with exact header counts and offsets. Types are unique, initial offsets are
strictly ordered and known extents cannot cross later mapped starts. This
closed profile requires positive entry counts and zero unused map words.
It does not turn unparsed variable counts into guessed lengths. Variable
sections, including unknown type codes, retain `unassessed_variable_extent`
and `unassessed_variable_contents`. Full map nonoverlap remains unproven.

Referenced string starts must be distinct, belong to the declared string-data
map section and begin at that section's initial offset collectively. Each
string is bounded by the next actual string start or next mapped start.
The parser checks the one-to-five-byte unsigned 32-bit LEB128 length, actual
MUTF-8 units, declared UTF-16 length and terminator. Nonminimal bounded ULEB
forms are not rejected merely for being nonminimal. Fixed-range and raw-string
contradictions raise `AndroidDexAnalysisError`, not a vulnerability finding.

MUTF-8 here is an encoding of **UTF-16 units**, not a Unicode scalar decoder.
Encoded NUL is legal. Isolated, reversed and paired surrogate units are legal
raw string data. Results retain integer units in original order. String IDs
must be strictly sorted and distinct by those units, not by MUTF-8 byte order,
Unicode scalar order, locale or normalized text. Higher-level name syntax
is not inferred from strings. Ordinary UTF-8 four-byte sequences and unsupported
overlong forms are outside the accepted MUTF-8 subset.

The observed Adler32 field is recomputed over bytes from offset 12; the SHA1
field is recomputed over bytes from offset 32. A mismatch rejects the result.
These are corruption/identity checks, not cryptographic signing authentication.
The report separately binds the exact decoded file with SHA256 and the entire
canonical model under a distinct model domain.

## Report and software ceilings

Metadata includes the owned original model, exact file/model addresses,
header fields, ordered map observations, string offsets and integer units,
an explicitly partial status, checksum consistency and all-false authority
and qualification flags. It retains supplied content, not sanitized data;
callers must not treat arbitrary retained strings as renderable names or code.
No output is executed, installed, resolved against a device or converted into
admission, target access or a qualified candidate.

| Local software ceiling | Limit |
| --- | ---: |
| Decoded file / canonical model / report bytes | 512 KiB / 1 MiB / 2 MiB |
| Model / report native nodes | 16,384 / 262,144 |
| Native and raw scalar-inclusive depth | 16 |
| Map entries / string IDs | 128 / 4,096 |
| Units per string / aggregate UTF-16 units | 4,096 / 65,536 |
| Cumulative work per public operation | 134,217,728 units |

Exact native families, cycles, repeated subtrees, queued children and escaped
ASCII byte costs are checked and funded before copying. Raw strings, depth,
nodes and signed64 integer grammar are bounded before JSON decoding or integer
conversion. File declarations are checked before section expansion. Unit
retention is funded before decoding/appending. All final report identities
use fixed-width reservations. Complete source, binary checksum, reconstruction,
encoding, export and equality work is funded before the first digest, including
both embedded and separately original plans in verification. Software exhaustion
is a domain error, not a structural contradiction or a fabricated negative.
Maximum combinations need not fit every complete replay operation.

These checks do not authenticate acquired files, contain arbitrary Python
callbacks or guarantee consistency against concurrent caller memory mutation.
They make no claim about APK signing, Android execution, maliciousness, actual
class/bytecode validity, live target permission or production qualification.

## Synthetic validation

Tests use an independent manual file encoder, checksum recalculation and
finite ULEB/MUTF-8 unit tables. They exercise truthful bad header/map/string
documents rather than only invalid checksum bytes. Ordinary positives include
NUL, unpaired/reversed surrogates, physical string order different from ID order,
unknown variable extents and deliberately unvalidated fixed contents. Native/raw
aliases, exact source replay, false cohashed metadata, detached ownership and
complete-operation prehash cost denials are covered without a database, APK,
device, network, provider, credential, process or runtime port.

The fresh public fixture is a 196-byte independently encoded file with raw
unit sequences `[0,65]`, `[72,101,108,108,111]` and `[55296]`. Its canonical
model is 336 bytes and report 4,783 bytes. Literal regression controls pin
`DXA-3D127A90FAF3E4D797F6BBAB7C33F484`, report digest
`sha256:3d127a90faf3e4d797f6bbab7c33f4847d7753c35f55a914dca39cf869d157c8`,
model digest
`sha256:a7fa488a9300cf4144a75c600ca571b1b44ec3ef16f1f6c3df9461d4ab53d2ac`
and exact file digest
`sha256:b71e003f3542b9a2e41cb83db6bf819a8201933344069afa635c9deec35bc970`.
These are synthetic content identities, not APK authentication evidence.
