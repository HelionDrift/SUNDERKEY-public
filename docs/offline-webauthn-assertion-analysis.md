# Supplied WebAuthn assertion/context arithmetic

This partial offline algorithm compares supplied bytes with a declared context. It
does not verify a credential, signature, user, relying party or authentication.
It uses no browser, authenticator, network, provider, credentials, clock or process.

The pinned primary source is the [W3C Recommendation of 25 August 2026](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/),
specifically sections 5.8.1, 6.1 and 7.2. The implementation is independently written.

## Existing ownership and narrow evidence

Component `webauthn_supplied_assertion_context_arithmetic` belongs to existing
`AOE-GA-D03-S08`, capability `army.ga.d03.s08`, vector `AV-GA-D03-S08-01`, package
`IWP2-AOE-GA-D03-S08` and wave `IW2-009`. Commander `AOE-GA-D03-CMD`, group owner
`AOE-HQ-03` and independent validator `AOE-HQ-19` remain unchanged. Blueprint:
`sha256:b3ed2155fb5865d00f551b389cfb9ba83d411c57361a208e51cb69ae7273bf79`.
This is A7.4 partial offline evidence, not specialist completion, qualification or
an amendment to signed SDK manifests, existing defaults or D016 live gates.

## Closed supplied model

The exact outer fields are `schema_version: 1`, `source_id`,
`authenticator_data_base64`, `client_data_json_base64` and `context`. The exact
context fields are `rp_id`, `challenge_base64`, `origin`, `cross_origin`,
`top_origin`, `user_verification_required` and `previous_sign_count`.

Byte fields contain canonical padded base64. Context text is nonempty printable
ASCII with explicit byte limits, not validated URL/domain syntax or ownership.
No case conversion, URL normalization, PSL lookup or RP/origin authorization is
performed. `cross_origin` and `user_verification_required` are exact booleans.
The previous counter is null or an exact native uint32; null means unavailable.
An empty challenge is allowed as a supplied byte premise, not a randomness,
freshness or challenge-quality endorsement.

`top_origin: null` means a declared absence expectation, not unavailable knowledge.
A string means an exact value and presence expectation and requires a true
declared cross-origin context. An observed missing optional `topOrigin` against
an expected string is a supplied-context mismatch, not a statement that all
WebAuthn clients must provide it. A true cross-origin observation with declared
null top origin can match when that optional member is absent. Present null
client fields are different from absent optional fields and reject malformed
known-field shapes.

## Actual computations and limits of meaning

The fixed 37-byte authenticator prefix provides the supplied RP hash, flags and
unsigned big-endian counter. UP, UV, BE and BS are observed bits, not independently
verified user/authenticator properties. UP is checked; UV is checked only against
the declared requirement. BS without BE cannot yield supported consistency.
AT, ED and future reserved bits leave their suffix semantics unassessed. No CBOR,
credential public key or extension bytes are parsed. An unextended supported
prefix must be exactly 37 bytes; extra bytes contradict that selected subset.
Known contradictions remain visible even when unsupported bits are also present.

The client JSON is parsed as well-formed UTF8, removing one leading BOM only for
parsing. All original bytes, including that BOM and exact JSON spelling/order,
remain the input to SHA-256. The unknown inner members and their ordering are
tolerated within the documented software limits. Their numeric lexicals are
bounded opaque internal tokens, never huge integer/float conversions or public
numeric metadata. Unknown member names/values are not semantically interpreted.
Duplicate keys reject ambiguous JSON. Outer models/reports remain closed exact
integer-only native JSON; unknown inner numbers do not loosen that boundary.

The checks compare `webauthn.get`, canonical unpadded base64url of the separately
supplied challenge, exact declared origin/cross/top context, RP hash and known
flags. Omitted observed `crossOrigin` is recorded as absent and interpreted as
false. The signature-input digest is computed from the original authenticator
bytes concatenated with SHA-256 of the complete original client JSON bytes.
That is a preimage computation, not signature verification.

Counter relations are `prior_unavailable`, `both_zero`, `increased` and
`nonincreasing_signal`. A nonincrease does not prove cloning or decide rejection;
no credential counter/state is updated. Registration, userHandle, AppID,
signature validation, origin authorization, freshness and current permission are
outside this algorithm. No full WebAuthn validity or vulnerability verdict exists.

## Public API and exact replay

`analyze_supplied_webauthn_assertion(model)` and
`analyze_supplied_webauthn_assertion_bytes(model_bytes=...)` return a frozen
`WebAuthnAssertionAnalysis` containing canonical JSON. Configuration, malformed
closed intake, ambiguous JSON and software exhaustion raise
`WebAuthnAssertionAnalysisError`; semantic mismatches are reported checks.
`component_fixture()` returns a fresh wholly synthetic benign literal model.

The report embeds its complete original model, raw-byte identities, fixed
ownership/bounds/limitations, known client/prefix fields, individual checks,
counter relation and unsupported reasons. `analysis_status` distinguishes
`consistent_with_supplied_checks`, `contradictory_supplied_checks` and
`unassessed_supported_profile`. Neither consistency nor exact replay authenticates
the input or grants authority. All effects are `none` and all promotion/authenticity
claims are false. Embedded base64 is unsanitized source retention, not redaction.

Source identity uses `sunderkey.offline-webauthn-assertion-model.v1`; report identity
uses `sunderkey.offline-webauthn-assertion-analysis.v1` and prefix `WAA-`. Model
member order and raw outer JSON whitespace do not change canonical model identity;
inner client bytes do. The report constructor, `from_dict`, `from_json`, `to_dict`
and `to_json` fully rederive the embedded source and exact canonical report.
Exports are detached. Coherently readdressing a false check does not bypass replay.

`verify_supplied_webauthn_assertion_analysis(report, model=original)` additionally
requires the separately supplied original model and returns a detached existing
report. Embedded replay alone does not establish that the caller selected the
right original source. No repository discovery or hidden context lookup occurs.

## Software-cost contract

| Resource | Ceiling |
| --- | ---: |
| Authenticator / client JSON / challenge bytes | 4,096 / 16,384 / 1,024 |
| RP ID / origin text bytes | 253 / 2,048 |
| Canonical model / report bytes | 65,536 / 262,144 |
| Model / client JSON / report nodes | 4,096 / 4,096 / 16,384 |
| Scalar-inclusive depth | 16 |
| Inner client numeric lexical bytes | 128 |
| Named checks, unsupported reasons and counter observation | 32 |
| Cumulative weighted work per public operation | 67,108,864 |

The limits are software costs, not WebAuthn authority or limits mandated by W3C.
The eight public paths are native analyze, bytes analyze, direct construction,
from-dict, from-JSON, to-dict, to-JSON and separate-original verification.
Properties use their export's independent replay budget. Simultaneous maxima need
not fit one operation; no claim is made that every nominal ceiling is reachable.

Native measurement includes exact JSON escape expansion, repeated strings,
queued nodes, aliases, cycles and scalar depth before copy/serialization. Raw
metadata/client guards precede JSON decoding and numeric conversion; base64
declared lengths precede decoding. Every operation carries one cumulative budget.

The hash-free plan reserves a complete worst-case report with final fixed-width
identities, maximal boolean encoding and a 64-character final-status slot. It then
funds conservative materialization/digest/preimage/sorted-encoding/body-copy and
equality buffers: 32 times report bytes, 16 times model bytes, 32 times decoded
input bytes and nodes, plus fixed RP/domain overhead. Replay additionally funds
actual report decoding and comparison; separate-original funds both complete
plans and comparison together before the first digest. No new cost charge or
output-ceiling discovery occurs after any RP, client, source or report digest.
This is weighted deterministic accounting, not CPU-time or process-memory isolation.

Tests distinguish real default byte/node boundaries from transparently reduced
report/work ceilings. All eight work paths have threshold and minus-one controls
that observe no digest before exhaustion and no later charge after hashing.
Independent octet/flag/context tables, raw-source/preimage controls and readdressed
false-output regressions are supplied, without authenticator/network execution.
