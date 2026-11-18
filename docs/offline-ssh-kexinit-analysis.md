# Supplied SSH KEXINIT selection arithmetic

This partial component computes finite name-list selection arithmetic over two
caller-supplied SSH_MSG_KEXINIT payloads. It performs no SSH acquisition,
connection, packet transmission, cryptographic key exchange or authentication.
Its output concerns supplied declarations, not actual negotiation or a completed
handshake. The synthetic example is not a recommended security configuration.

## Public interface

The module is `sunderkey.offline_ssh_kexinit_analysis`.

- `analyze_supplied_ssh_kexinit_pair(model)` returns `SshKexinitAnalysis`.
- `analyze_supplied_ssh_kexinit_pair_bytes(*, model_bytes)` accepts exact native
  bytes containing bounded ASCII JSON.
- `verify_supplied_ssh_kexinit_analysis(report, *, model)` rederives the embedded
  source and the separately supplied original source in one funded operation.
- `SshKexinitAnalysis(document_json)`, `from_dict`, `from_json`, `to_dict` and
  `to_json` rederive the complete report, not just its claimed hash.
- `component_fixture()` returns a fresh synthetic model without hashing,
  acquiring data, generating keys or importing a client.

The source is an exact native dictionary with exactly four fields:

```json
{
  "schema_version": 1,
  "source_id": "synthetic-kexinit",
  "client_payload_base64": "canonical padded standard base64",
  "server_payload_base64": "canonical padded standard base64"
}
```

Each base64 value contains only the KEXINIT message payload: byte type 20,
sixteen cookie bytes, ten uint32-length-prefixed name-lists, one received boolean
octet and one received uint32 reserved field. No packet length, padding, MAC,
identification line or TCP framing is supplied. Extra or truncated bytes reject.
The source identity uses one to 64 ASCII letters, digits, underscore, dot, colon
or hyphen, beginning with a letter or digit.

## Selected semantics

Names remain ordered, case-sensitive and duplicate-preserving. The closed
software subset accepts nonempty entries of at most 64 non-whitespace printable
ASCII bytes (33 through 126) excluding comma; a whole empty name-list is
well-framed. Empty required
algorithm declarations are adverse contextual observations, while empty
language declarations are accepted. Language interpretation, IANA-name validity
and namespace ownership are not checked. Every received nonzero boolean means
true; the raw
octet and whether its sender encoding is zero/one remain observations, not a
fabricated receiver rejection. See [RFC 4251 sections 5 and 6](https://www.rfc-editor.org/rfc/rfc4251.html#section-5).

The raw uint32 reserved value is retained and ignored for base selection. A
nonzero value is not silently zeroed, rejected by an unaware receiver, or removed
from the payload hash. This follows the received-field correction in
[verified erratum 4533](https://www.rfc-editor.org/rfc/inline-errata/rfc4253.html#eid4533).

For ordinary supported declarations, selection follows client preference for
each direction. KEX requires a common signature-capable host-key algorithm in
the finite supported table. Literal first-common names are separately reported.
An earlier unknown common KEX or host-key name cannot be skipped to assert a
later supported winner. A known signing host-key witness can establish that a
specific supported KEX is eligible without proving the first compatible host-key
choice. See [RFC 4253 sections 6.2 through 7.1 and 8](https://www.rfc-editor.org/rfc/rfc4253.html#section-7.1).

The tables include named legacy controls and a small modern subset:

- KEX: `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`,
  `diffie-hellman-group14-sha256` and group15 through group18 with `sha512`.
  The additional labels are defined in [RFC 8268 section 3](https://www.rfc-editor.org/rfc/rfc8268.html#section-3).
- Signing host keys: `ssh-dss`, `ssh-rsa`, `pgp-sign-rsa`, `pgp-sign-dss`,
  `rsa-sha2-256` and `rsa-sha2-512`. Sharing an RSA key encoding does not make
  algorithm names interchangeable. See [RFC 8332 section 3](https://www.rfc-editor.org/rfc/rfc8332.html#section-3).
- Ciphers: AES128/192/256-CBC, AES128/192/256-CTR and explicit `none`. The CTR
  labels are defined in [RFC 4344 section 4](https://www.rfc-editor.org/rfc/rfc4344.html#section-4).
- MACs: `hmac-sha1`, `hmac-sha1-96`, `hmac-md5`, `hmac-md5-96`, `none`,
  `hmac-sha2-256` and `hmac-sha2-512`. See [RFC 6668 section 2](https://www.rfc-editor.org/rfc/rfc6668.html#section-2).
- Compression: `none` and `zlib`.

Tables provide only name-specific capability arithmetic. They do not compute
crypto, inspect keys, assess strength, or recommend legacy or modern labels.
All listed host-key capabilities are signature-only; encryption capability is
never inferred.

Correct-role `ext-info-c` and `ext-info-s` indicators are observed and excluded
as KEX candidates. Incorrect-role indicators are declaration violations, not
proof of a disconnect. No extension message is supplied or evaluated. Other
modern marker behavior remains deferred, without prefix stripping. See
[RFC 8308 sections 2.1 and 2.2](https://www.rfc-editor.org/rfc/rfc8308.html#section-2.1).

Unknown or AEAD first-common cipher labels withhold the corresponding MAC
semantic result, even when the literal MAC lists have no common name. This
avoids applying independent ordinary-MAC rules to a coupled construction such
as [RFC 5647 section 5.1](https://www.rfc-editor.org/rfc/rfc5647.html#section-5.1).
An ordinary supported cipher permits independent finite MAC selection. Unknown
first-common MAC or compression names retain uncertainty and any known fallback
witness; that fallback is not asserted as the selected algorithm.

Optimistic observations retain the truth octet and preference equalities. Their
rules are explicitly conditional on a guessed packet following and on the
supported declaration subset. No next packet, packet existence, actual discard
or key-exchange completion is claimed.

## Results and replay

The report uses `analysis_id` and `analysis_sha256`, exact payload SHA256 fields,
`source_model` and `source_model_sha256`. It contains both decoded wire
observations, literal first-common names, finite semantic candidates,
declaration violations, unassessed selection semantics and conditional
optimistic observations. Known declaration contradictions dominate unresolved
selection semantics. The only aggregate outcomes are:

- `known_declaration_contradictions`
- `unassessed_selection_semantics`
- `consistent_supported_selection_declarations`

None means actual handshake success or failure. All claims are false and all
effects are `none`. The address domain is
`sunderkey.offline-ssh-kexinit-analysis.v1`; the model has a separate domain.
Hashes are unsigned mechanical addresses, not source authenticity.

Canonical report parsing rederives every field and rejects coherently rehashed
false results. A coherently changed source can create a different internally
consistent report, so positive source consistency requires the separately
original verifier. Native exports are detached. Raw model JSON spelling is not
retained: parsed canonical snapshot provenance differs from raw JSON byte
provenance. Original decoded payload octets, including nonzero reserved fields
and boolean encodings, are retained in the canonical base64 source.

Exact native families, bounded integer-only JSON, duplicate raw keys, cycles,
scalar-inclusive depth and queued nodes are checked before expansive work.
Valid pre-entry source replacement and arbitrary concurrent caller mutation are
not authenticated or isolated by this pure component.

## Software ceilings

Independent, simultaneous software ceilings apply:

| Quantity | Maximum |
| --- | ---: |
| Each supplied payload | 32,768 bytes |
| Each name-list | 8,192 bytes |
| Entries per name-list | 128 |
| Each entry | 64 bytes |
| Model or raw model JSON | 131,072 bytes |
| Complete retained report | 1,048,576 bytes |
| Model / report nodes | 4,096 / 65,536 |
| Scalar-inclusive depth | 16 |
| Native/raw decoded text value | 43,692 bytes |
| One public operation's cumulative work | 134,217,728 units |

The complete source, binary parsing, matching, retained output, copies,
serializations, equality and embedded/separately-original plans are funded
before the first SHA in each of the eight public operation forms. No work is
charged after hashing starts. Repeated shared native subtrees count repeatedly;
escape-heavy strings count against encoded document budgets. No unrestricted
expansion or silent truncation occurs. A malformed subset or software ceiling
raises `SshKexinitAnalysisError`, not a fabricated protocol failure. Not every
combination of individual maxima fits the aggregate report/work ceilings.

## Existing ownership and acceptance boundary

The partial component maps to `AOE-GC-D12-S06`, `army.gc.d12.s06`,
`AV-GC-D12-S06-01`, `IWP2-AOE-GC-D12-S06`, wave `IW2-006`, commander
`AOE-GC-D12-CMD`, command group `AOE-HQ-05` and validator `AOE-HQ-19`. Its
existing blueprint SHA256 is
`ba3ad230cf7bc5d013136c51fb64bd95c7966f7ee7123a2aa3eb80879ffc1b20`.
Initial evidence is `A7.4` only. No candidate readiness, routing, authority,
qualification or full-specialist implementation is promoted.

The focused suite uses an independent binary encoder and positional list
oracle, truncated prefixes, literal-versus-capability uncertainty, directional
MAC controls, role indicators, received boolean/reserved fields, actual and
reduced software boundaries, full source replay and all eight prehash funding
boundaries. It uses no endpoint, socket, provider, process, SSH client or key.
