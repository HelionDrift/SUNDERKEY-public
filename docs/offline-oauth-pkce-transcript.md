# Supplied OAuth authorization-code and PKCE transcript arithmetic

`sunderkey.offline_oauth_pkce_transcript` checks six digest bindings across
three separately supplied declarations. It is partial offline evidence for
existing profile `AOE-GA-D03-S04`, capability `identity.oauth-oidc`, vector
`AV-GA-D03-S04-01`, package `IWP2-AOE-GA-D03-S04`, wave `IW2-005`, commander
`AOE-GA-D03-CMD`, group owner `AOE-HQ-03`, independent validator `AOE-HQ-19`,
and blueprint `sha256:d194f3d0b1c6f384a679c104bc4dfd91e5ef5d4685cf9c837827401153eacc7a`.
It contributes only to A7.4 repository evidence. It is not a qualified
specialist, operational OAuth client, login decision, token validator, or
permission grant.

The module makes no network, provider, browser, credential, file, process,
token-endpoint, or target call. `component_fixture()` returns a fresh synthetic
model with no raw code, state, redirect URI, or code verifier. Do not place
operational secrets in source identifiers or client identifiers.

## Public interface and closed input

```python
analyze_supplied_oauth_pkce_transcript(model) -> OAuthPkceTranscriptAnalysis
analyze_supplied_oauth_pkce_transcript_bytes(*, model_bytes: bytes) -> OAuthPkceTranscriptAnalysis
verify_supplied_oauth_pkce_transcript(report, *, model) -> OAuthPkceTranscriptAnalysis
OAuthPkceTranscriptAnalysis.from_dict(document)
OAuthPkceTranscriptAnalysis.from_json(document_json)
report.to_dict()
report.to_json()
```

The exact root keys are `schema_version`, `source_id`,
`authorization_request`, `authorization_response`, and `token_request`.
`schema_version` is native integer 1, not a boolean or integer subclass. All
four source IDs must be distinct, bounded printable ASCII identifiers. Stage
`complete` fields are exact native booleans. Each stage has the following
exact keys:

| Stage | Other keys |
| --- | --- |
| `authorization_request` | `response_type`, `client_id`, `redirect_uri_sha256`, `state_sha256`, `code_challenge_method`, `code_challenge` |
| `authorization_response` | `callback_redirect_target_declared`, `callback_redirect_uri_sha256`, `state_sha256`, `code_sha256` |
| `token_request` | `grant_type`, `client_id`, `redirect_uri_sha256`, `code_sha256`, `code_verifier_sha256` |

Every stage also has `source_id` and `complete`. This is a narrow declared
successful public-client code-flow shape: `response_type` must be `code`,
`grant_type` must be `authorization_code`, and the explicitly supplied PKCE
method must be `S256`. Other methods, grant types, confidential-client
authentication, error redirects, token responses, OIDC ID tokens and nonce
handling are outside the subset. Source completeness is a caller declaration,
not evidence of a real HTTP exchange.

`client_id` is bounded printable ASCII and is required in the authorization
request. It may be null in the token request. All fields ending `_sha256` are
canonical `sha256:` plus 64 lowercase hexadecimal digits or null. Null means
unavailable when that stage is incomplete; with `complete: true`, it declares
absence. The `code_challenge` must be exactly canonical unpadded base64url of
32 bytes. Even a correctly shaped value is not proof that the server bound it
to an authorization code.

`callback_redirect_uri_sha256` is a digest of a separately supplied redirect
*target URI after removing the OAuth response parameters*, not a digest of
the full callback URL containing `code` and `state`. The exact native boolean
`callback_redirect_target_declared` asserts that this normalization premise
was made by the caller. The module neither parses the callback URL nor
authenticates that premise. If the flag is false or the normalized target
digest is unavailable, the callback-redirect check is `unknown` even when a
different digest happens to equal the authorization-request redirect digest.

For the PKCE check, the token stage supplies only a *declared SHA-256 digest*
of the verifier. The analyzer base64url-encodes those 32 declared digest
bytes and compares that string with the authorization request challenge. This
is the RFC 7636 S256 relation if the digest really came from the ASCII
verifier. The analyzer never receives the verifier and cannot establish that
premise or that the token endpoint actually saw or verified it.

## Deterministic conclusions

Six independent checks bind client ID, authorization-code digest, state
digest, callback redirect-URI digest, token-request redirect-URI digest, and
the declared PKCE S256 digest relation. Each check is `matched`,
`contradicted`, or `unknown`, with both supporting source IDs. An exact
digest mismatch is a contradiction in the supplied declarations. If a
required value is null in a stage declared complete, the missing declaration
is a contradiction within that asserted success-path transcript. In an
incomplete stage, null is unknown. If no state or redirect URI was supplied
in the authorization request, no source-bound equality can be inferred for
that binding, so it remains unknown. A full callback URL digest is never
compared as though it were the original redirect URI.

The overall status is `contradicted` if any check contradicts, otherwise
`unknown` if any check is unknown, otherwise
`consistent_with_supplied_bindings`. The last status is **not** a successful
authorization, proof of code redemption, token validity, OIDC verification,
CSRF resistance, client authentication, or permission decision. It does not
establish that supplied digests were computed from actual protocol values.
The existing `RedirectPKCEEvidence` contract stores digest evidence but does
not check this transcript; the existing pinned OIDC verifier performs a
different authenticated token check. Neither is silently invoked or replaced.

## Replay and local software limits

Reports are immutable wrappers over canonical JSON. Their content address
binds the complete original digest-only model, all check rows, metadata,
limitations, no-effect flags and fixed bounds. `from_dict`, `from_json`,
`to_dict`, `to_json`, the native constructor and the verifier all rederive the
entire report from its embedded original. The verifier also requires a
separately supplied original model and compares both derivations. Export
alone is not independent current-source verification. Readdressing a false
conclusion cannot make it replay correctly.

Model JSON is at most 256 KiB, report JSON at most 512 KiB, native model and
report at most 4,096 and 8,192 nodes, native nesting at most 16, individual
strings at most 512 characters, and one complete public operation has a
32 MiB cumulative software-work ceiling. Raw JSON input is ASCII, duplicate
key safe, signed-64 integer bounded and prechecked for bytes, nodes,
depth and scalar length before decoding. Native inputs require exact builtin
JSON types, without bool/int aliases, subclasses or cycles. Cost planning
funds complete source/report retention, canonicalization, both digests,
comparison and export before the first SHA-256 call. Separate-original
verification funds both plans under one work budget. These are local
software-cost limits, not OAuth or deployment authority. Individual maxima
do not promise that every combination fits the cumulative ceiling.

Primary sources checked:

- [RFC 6749, authorization-code request, response and token request](https://www.rfc-editor.org/rfc/rfc6749#section-4.1)
- [RFC 7636, S256 transformation and verification relation](https://www.rfc-editor.org/rfc/rfc7636#section-4)
