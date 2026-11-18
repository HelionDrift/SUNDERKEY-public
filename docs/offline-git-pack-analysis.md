# Supplied Git PACK reconstruction

This partial R0 component performs finite arithmetic on caller-supplied bytes.
It does not open a repository, fetch objects, discover refs, create a checkout,
execute content or contact a provider. All declared effects are `none` and all
authentication, safety, full-format, live-use and qualification claims are false.

The component is `git_supplied_pack_ofs_delta_reconstruction`, assigned to
AOE-GC-D17-S01 / army.gc.d17.s01 / AV-GC-D17-S01-01 /
IWP2-AOE-GC-D17-S01 / IW2-013, commanded by AOE-GC-D17-CMD under AOE-HQ-05
and independently validated by AOE-HQ-19. Its blueprint binding is
sha256:a9bc1a2fbb55b2917d9bfd1cfafade6c599bc01a0fb47961f3ebfc79b3bab1c4.
Only A7.4 supplies initial evidence. This is not a complete or qualified Git
platform specialist.

## Public input and output

`analyze_supplied_git_pack(model)` accepts exactly four native JSON fields:

```json
{"schema_version":1,"source_id":"synthetic-pack","object_format":"sha1","pack_base64":"..."}
```

`source_id` is an ASCII declaration of at most 64 characters, not authenticated
provenance. `pack_base64` must be canonical padded standard base64 for one whole
PACK. `analyze_supplied_git_pack_bytes(*, model_bytes)` accepts bounded native
ASCII JSON bytes, rejecting duplicate keys and unsupported primitive families.
Raw JSON may have insignificant whitespace or escaped ASCII spelling: its
parsed canonical source model is addressed, not the original raw JSON spelling.
The PACK byte spelling and order are preserved exactly.

`GitPackAnalysis` is frozen and owns canonical `document_json`. Its constructor,
`from_dict`, `from_json`, `to_dict` and `to_json` rederive the complete embedded
source. Report JSON itself must have the exact canonical spelling. Exports are
detached native records. `verify_supplied_git_pack_analysis(report, *, model)`
additionally reconstructs the separately supplied original model, under the
same cumulative operation budget, and requires exact report equality. A valid
alternative source can produce a valid alternative report; it does not verify
the original source. Unsigned hashes or metadata alone establish no authority.
Valid pre-entry changes to an entire source model are new supplied input. No
arbitrary Python callback sandbox, concurrent-memory protection or authenticated
external custody is claimed.

`component_fixture()` returns a fresh four-field inert model. It contains a base
blob `abcdef` and an OFS delta reconstructing `abXYef`. The component retains
ordered entry offsets, compressed consumption, inflated instruction length,
resolved type, reconstructed base64 bytes, delta counts/depth and mechanical
object SHA1. Duplicate objects and original order are not deduplicated.

The report has `analysis_id`, `analysis_sha256`, `source_model`,
`source_model_sha256` and `source_pack_sha256`. Source-model and report SHA256
use separate version-one domains. The generic whole-PACK SHA256 includes its
trailer, while its declared PACK SHA1 covers only the preceding PACK bytes.
Git object SHA1 includes the resolved type, space, decimal reconstructed size,
NUL and body. SHA1 is used only for this historical format identity/checksum,
not as a security recommendation, signature or authentication mechanism.

## Selected format semantics

Supported versions are 2 and 3, with base types commit/tree/blob/tag and backward
OFS_DELTA. A delta must point to an earlier proven entry start, not a header or
compressed-data byte. OFS distance uses its distinct biased high-group-first
encoding. Entry-header size is the inflated entry size, so for a delta it is
instruction length, not reconstructed length. Internal base and result sizes
must match the retained base and exact reconstructed result. Copy operand bits
retain fixed byte positions when absent; zero effective copy size means 65536.
Insert lengths are 1 through 127; zero instruction is reserved. These selected
rules follow the [Git 2.54 PACK specification](https://git-scm.com/docs/gitformat-pack/2.54.0).

REF_DELTA, thin packs, SHA256 object format, reserved types and unsupported PACK
versions are explicitly refused as outside this subset. This does not label
all deferred Git formats malformed. Type zero, truncated supported fields,
invalid offsets, mismatched sizes, instruction overruns and non-exhaustive
counted bodies are typed `GitPackAnalysisError` refusals. Commit, tree and tag
bodies remain opaque: no content grammar, tree paths, refs or reachability is
validated.

A structurally supported complete reconstruction with a bad declared PACK
SHA1 returns the fixed-shape adverse outcome
`declared_pack_checksum_mismatch`. A matching checksum returns
`supported_pack_reconstruction_consistent`, meaning only these selected
structural and reconstruction checks. Neither status authenticates supplied
data or proves full repository validity. Malformed/truncated zlib streams or
Adler checksums are domain refusals, not a completed reconstruction.

## Bounded compressed intake

The product uses the standard-library zlib decoder for DEFLATE, not a copied
upstream decoder. CM, window size and FCHECK are checked; preset dictionaries
are outside this closed subset. Each call reserves its compressed slice,
possible input tails, bounded returned output and destination retention before
calling the decoder. Input chunks are at most 4096 bytes and `max_length` is
always positive, at most 4096, with one extra sentinel byte relative to remaining
declared output. Over-expansion is rejected before extending retained output.
An exact output length still requires the zlib checksum and EOF, using a cap of
one if necessary. Only stream start plus exactly consumed input determines the
next entry; EOF `unused_data` and non-EOF `unconsumed_tail` are alternatives,
not two independent suffix lengths to subtract together.

No unrestricted `decompress` or `flush` is used. `flush(length)` is an initial
buffer size, not an output ceiling. This distinction and EOF/tail behavior are
documented in [Python 3.11 zlib](https://docs.python.org/3.11/library/zlib.html).
The wrapper/checksum and compression definitions are
[RFC1950](https://www.rfc-editor.org/rfc/rfc1950.html) and
[RFC1951](https://www.rfc-editor.org/rfc/rfc1951.html). Linked zlib execution is
not a general CPU sandbox or proof of library security.

## Software ceilings and replay funding

These are transparent software limits, not maxima guaranteed by Git:

| Ceiling | Bound |
| --- | ---: |
| PACK bytes | 512 KiB |
| Canonical model bytes | 1 MiB |
| Canonical report bytes | 2 MiB |
| Counted objects | 256 |
| One inflated entry or reconstructed object | 512 KiB |
| Aggregate inflated entry bytes | 2 MiB |
| Aggregate reconstructed bytes | 2 MiB |
| Delta dependency depth | 32 |
| Aggregate delta instructions | 8192 |
| Inflate calls per complete public operation | 4096 |
| Compressed input chunk / returned output cap | 4096 bytes each |
| Model / report native nodes | 16384 / 262144 |
| Scalar-inclusive native/raw depth | 16 |
| One ASCII metadata string | 699052 characters |
| Cumulative charged work per public operation | 128 MiB units |

The work accounting is deterministic conservative byte/node/operation charging,
not a wall-clock or exact Python heap measurement. Native graphs are bounded
before copying or serialization, including repeated shared containers; cycles
are rejected. Raw lexical depth, nodes, strings and signed64 integers are
bounded before JSON decoding or integer conversion. Unsupported subclasses,
bool/float aliases, duplicate keys and malformed primitive text are refused.

Object reconstruction, instruction copies, output encoding, full retained report
and final hash/equality/serialization passes are funded before the first SHA1
or SHA256 in all eight public forms: native/bytes analysis, direct constructor,
from-dict/from-JSON, dict/JSON export and separate-original verification. Both
source plans in separate-original verification share one budget, with no nested
reset. Outcome/hash placeholders reserve both checksum branches. Software
limits are simultaneous: a large accepted compressed source or aggregate
reconstruction can still exceed base64-retained report or cumulative work limits.
There is no truncation, implicit normalization or partially clean report on
budget exhaustion.

## Offline regression evidence

The tests independently encode stored DEFLATE, Adler32, PACK entry sizes, OFS
distances and delta copy/insert instructions, then compare actual reconstructed
bytes and loose-object identities. They exercise empty/duplicate objects, all
four base types, delta chains, omitted operands, checksum mismatch, truncation,
stream boundaries, fixed/dynamic compressed controls and hostile references.
Genuine default input/object/count/depth/instruction/report boundaries are
distinguished from reduced-limit placement checks. Every public work boundary
has exact measured funding and one-less denial before either SHA family.
Coherently readdressed false metadata must fail semantic replay; separately
supplied alternate original models must fail original-source verification.

All fixtures are synthetic bytes in memory. No repository, Git executable,
network, credential, provider, checkout or live target is used. This evidence
does not establish production acceptance, independent-host custody or security.
