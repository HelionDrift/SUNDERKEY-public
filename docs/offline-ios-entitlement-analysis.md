# Supplied iOS entitlement declaration consistency

This pure component compares three decoded entitlement declarations from one
caller-supplied application map with a supplied profile allowlist. It does not
acquire or parse a provisioning profile, executable, IPA, plist, CMS or DER. No
signature, source authenticity, provisioning validity, installation, authorized
execution or effective keychain access is established by a match.

## Existing ownership and API

Component `ios_supplied_entitlement_declaration_consistency` belongs to
AOE-GB-D08-S07, capability army.gb.d08.s07, vector AV-GB-D08-S07-01, work package
IWP2-AOE-GB-D08-S07 and wave IW2-011. Commander is AOE-GB-D08-CMD; group owner and
independent validator are AOE-HQ-04 and AOE-HQ-19. The existing blueprint address is
sha256:4c60c70e0dc5c482d661650a82790226acf8b54b540db5cdde766a8ea19a04e6.
Initial evidence is A7.4 only. All effects remain `none` and all promotion flags
remain false. Existing specialist, signed domains and live gates are unchanged.

The actual synthetic fixture addresses are
IEA-6B521E7012850EFFCFE54D67DA106371 and
sha256:6b521e7012850effcfe54d67da106371a88c37b628c4f1de9ca2ad133c9532b6;
its source model is
sha256:3ff969c2ee9ebd6628540ba8482e6324965e935e1a9834024ecd39afd0441fb0.
Its four claims match five supplied grants, with distinct App ID prefix/Team ID
and an exact `com.apple.token` entry. These are pure test vectors, not Apple
credentials, acquired declarations or entitlement authorization.

- `analyze_supplied_ios_entitlements(model)` returns `IosEntitlementAnalysis`.
- `analyze_supplied_ios_entitlements_bytes(*, model_bytes)` accepts exact native
  bytes containing bounded ASCII JSON, not plist or binary profile bytes.
- `component_fixture()` returns a fresh inert public model, not acquired evidence.
- `IosEntitlementAnalysis(document_json)`, `.from_dict(document)` and
  `.from_json(document_json)` rederive the complete embedded original model.
- `.to_dict()` and `.to_json()` revalidate full embedded-source replay at use.
- `verify_supplied_ios_entitlement_analysis(report, *, model)` additionally joins
  the report to a separately supplied original model.
- Malformed, unsupported closed-model shapes, software exhaustion and false
  replay raise `IosEntitlementAnalysisError` without I/O.

## Exact model

The root fields are exactly:

```json
{
  "schema_version": 1,
  "application_entitlements": {},
  "profile_entitlements": {},
  "coverage": {
    "application_entitlements_complete": true,
    "profile_entitlements_complete": true
  },
  "unmodeled_application_entitlement_keys": [],
  "unmodeled_profile_entitlement_keys": []
}
```

This is a projection schema, not Apple's profile schema. Each map contains only
optional `application-identifier`, `com.apple.developer.team-identifier` and
`keychain-access-groups` keys. Null is not a value or an unknown marker for these
keys. Omission declares no supplied claim/grant; completeness determines whether
absence of a profile grant can support a mismatch observation. Empty application
maps and empty group arrays claim nothing; no required entitlement or default
keychain group is invented.

Application identifiers have a ten-character ASCII alphanumeric prefix, a dot
and a nonempty dotted suffix. Team identifiers are literal ten-character ASCII
alphanumeric strings. The two values are independent; their equality is not a
prerequisite. Dotted components use ASCII letters, digits and hyphens with no
empty component. These lexical choices are a conservative software subset, not
a certification of every Apple identifier format.

Group values use the same nonempty dotted-component character subset without a
required App ID prefix or number of components. Exact `com.apple.token` is
supported. No rule forces every group to start with the application's prefix.
Every group still needs an exact or supported wildcard profile grant to match.
Application values must be concrete. Profile application-identifier and group
grants can be literal or have exactly one final dotted `*` component. Only that
nonempty literal prefix is a pattern; interior stars, bare stars and question
marks are outside this software subset. Team grants never use wildcards.

Arrays are unique and preserve original order in source identity. Unmodeled
entitlement key arrays contain only names, not arbitrary entitlement values.
Their names cannot duplicate each other or shadow a projected key. Missing,
unknown root/map fields and malformed native values are rejected, not inferred.

## Mathematics and uncertainty

The profile map is an allowlist, not a required exact copy of application claims.
Unused grants are harmless to this arithmetic. Each known application claim
produces a row with its key/value, all sorted matching grants and one outcome:
`matched_profile_allowlist`, `not_in_profile_allowlist`, or
`profile_allowlist_unavailable`. Comparisons are literal and case-sensitive. A
supported terminal wildcard matches a concrete claim beginning with its entire
literal prefix, including the dot before the star.

Complete profile coverage with no matching grant produces a supplied mismatch.
Incomplete profile coverage instead labels that unmatched claim unavailable;
omitted grants could change the result. Known matching grants remain observations
even when the inventory is incomplete. Any incomplete application/profile
projection or any unmodeled entitlement key makes the overall result
`inconclusive`. Otherwise, known mismatches yield `inconsistent_supplied_subset`;
no known mismatches yields `consistent_supplied_subset`. Known mismatches remain
labeled alongside uncertainty, without pretending comprehensive verification.

Source arrays and exact supplied identifiers are retained, while result rows and
matching witnesses are sorted deterministically. An unused-grant substitution or
array permutation can preserve arithmetic while changing source/report identity.
Embedded-source replay accepts a truthful alternate model, but separate-original
verification rejects it as evidence for a different original model.

Apple's official [TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)
describes allowlist matching, profile wildcards and the `com.apple.token` example.
Its complete official [DocC representation](https://developer.apple.com/tutorials/data/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles.json)
also distinguishes modern DER truth from the readable property map. The older
[TN2415](https://developer.apple.com/library/archive/technotes/tn2415/_index.html)
explains entitlement comparison and App ID prefix issues. This algorithm uses
those notes only for declared three-key arithmetic. It does not apply every
historical profile rule, inspect actual signatures or replace Apple's validators.

## Native, raw and operation boundaries

Source/report ceilings are 256 KiB/1 MiB, 8,192/32,768 native visited nodes and
depths 16/20, including scalars with root depth one. Printable ASCII strings are
bounded at 512 characters; entitlement values have a narrower 256-character cap.
The supported maps have three possible keys, with a defensive 64-key ceiling;
each side has at most 64 keychain groups and 64 unmodeled key names. No claim is
made that all combinations of individual maxima fit the aggregate budgets.

Exact native dictionaries, lists, string keys, integer schema and boolean
completeness are required. Subclasses, bool/integer or float/integer aliases,
floats, nonfinite values, cycles, oversized native integers and duplicate raw
members are denied. Every repeated shared subtree is charged. Native capture
accounts for quote/backslash escaping and structural punctuation before copying.
Raw ASCII length, decoded string length, escapes, scalar-inclusive depth, lexical
nodes and signed-64 integer magnitude/spelling are checked before JSON decoding.
Bytes copying is funded before decoding; arbitrary huge integer conversion is
not attempted.

Every public operation has one cumulative 8,388,608-unit work budget. Capture,
comparisons, matching witnesses, retained rows, complete output, full replay,
canonical equality and final serialization are funded before the first source
or report digest. Separately supplied verification funds both complete plans in
the same budget before hashing either. Row bytes/nodes are bounded before append.
Exhaustion is a software error, not a finding about an app or profile. Exact-limit
and one-below tests observe all public boundaries with hashing hooks denied.

Canonical ASCII JSON uses sorted object keys and original array order. The source
digest binds the parsed projection, not raw JSON spelling or acquisition truth.
The report uses `analysis_id`, `analysis_sha256`, `source_model` and
`source_model_sha256`. Complete semantic replay is distinct from authentication.
The frozen wrapper owns detached data and denies false/late-mutated exports; it
does not isolate arbitrary hostile Python code or concurrently changing memory.
Supplied identifiers are retained, so this report is not sanitized for publishing.

## Unassessed boundaries

No CMS/DER/certificate/signature validation, XML/plist/IPA/MachO parsing, profile
expiration, devices, app extensions, distribution channel, entitlement issuance,
operating-system checks, code signing, installation, keychain calls, revocation,
current authority, network, credential or qualification behavior is evaluated.
Unmodeled keys such as get-task-allow, app groups, push and iCloud cannot be
promoted to verified semantics. The tests use inert maps, an independent finite
prefix-component oracle, literal fixture addresses, coherent false readdressing,
original-source substitution and predecoder/prehash resource controls.
