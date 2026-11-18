# Supplied Windows DACL projection analysis

`sunderkey.offline_windows_dacl_analysis` evaluates one bounded inert DACL
projection against explicitly supplied SID usage. It does not call Windows,
inspect a process token or target, acquire descriptors, issue commands, contact
providers, use credentials or authorize access. Only standard-library software
is needed. These are observations about caller assertions, not effective
Windows access, account membership or descriptor authenticity.

## Existing ownership and scope

The partial specialist is `AOE-GC-D11-S05`, capability `army.gc.d11.s05`, vector
`AV-GC-D11-S05-01`, package `IWP2-AOE-GC-D11-S05`, wave `IW2-005`. Its command
is `AOE-GC-D11-CMD`, group commander `AOE-HQ-05`, independent validator
`AOE-HQ-19`, and blueprint digest
`sha256:1716965e4b35f85ef7b237f4e95fabb67d825d13a477c0772ebd574b9e6d1699`.

This adds a partial candidate component under the approved D016 offline
sequencing amendment. It does not replace the original six reference SDKs,
change original strategy or manifest identities, implement a graph handoff,
satisfy real-host containment, complete GPO or AD delegation coverage, or
promote A7.4 from its infrastructure-blocked state. All live entry,
qualification, routing and deployment requirements remain unchanged.

## Closed supplied model

`analyze_supplied_windows_dacl(model)` accepts this exact native JSON shape:

```json
{
  "schema_version": 1,
  "security_descriptor": {
    "owner_sid": "S-1-5-21-100-200-300-1000",
    "group_sid": "S-1-5-32-545",
    "dacl_state": "present",
    "aces": [
      {"ace_type": 0, "sid": "S-1-5-21-100-200-300-1000", "mask": 1, "flags": 0},
      {"ace_type": 0, "sid": "S-1-5-32-545", "mask": 2, "flags": 16}
    ]
  },
  "token_sids": [
    {"sid": "S-1-5-21-100-200-300-1000", "usage": "enabled"},
    {"sid": "S-1-5-32-545", "usage": "enabled"}
  ],
  "desired_access": 3
}
```

This is a stored projection, not SDDL or a binary security descriptor. Every
SID usage is explicit: `enabled`, `deny_only` or `disabled`. No user SID is
implicitly enabled, and no Everyone, owner, group or parent entry is added.
A user SID can itself be deny-only. Duplicate or conflicting SID declarations
are refused. [Microsoft token SID attributes](https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-attributes-in-an-access-token)

The conservative SID spelling subset uses revision 1, a decimal identifier
authority below 2^32, and 1 to 15 decimal uint32 subauthorities without leading
zeros. Larger hexadecimal identifier authorities are outside this software
subset, not universally malformed Windows SIDs. SDDL aliases and account
names are not resolved. [Microsoft SID string syntax](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c92a27b1-c772-4fa7-a432-15df5f1b66a1),
[Microsoft SID packet bounds](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/f992ad60-0fe4-4b87-9fed-beb478836861)

## Supported arithmetic

The supported calculation is a nonzero, already-specific low16 desired mask
with standard allow type 0 and deny type 1 ACEs using low16 masks. These bits
are not mapped to file, registry, directory or other object-specific meanings.
Caller-supplied owner and group SIDs are bound metadata, not implied grants.
Standard owner rights, generic mapping, MAXIMUM_ALLOWED and privilege rights
are deliberately outside the subset. [Microsoft access-mask format](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask-format)

The analyzer preserves actual supplied ACE order. An enabled SID matches both
allow and deny. A deny-only SID matches deny only; a disabled or absent SID is
ignored. Allows satisfy remaining requested bits. A deny intersecting any
remaining requested bit terminates with DACL denial. Satisfying all requested
bits terminates with DACL allowance. Exhaustion with remaining bits is implicit
DACL denial. A denied whole request retains `allowed_mask` zero even if an
earlier ACE satisfied some bits. No actual access receipt is issued.
[Microsoft ordered evaluation](https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object),
[Microsoft detailed algorithm and owner exceptions](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/4f1bbcbb-814a-4c70-a11e-2a5b8779a6f9)

`dacl_state` distinguishes `absent`, `null` and `present`. Null and absent have
no DACL restriction for supported requested bits and cannot declare ACEs.
Present with no ACEs denies those bits. This does not override privileges,
integrity controls or the actual owner's standard rights.
[Microsoft null and empty DACLs](https://learn.microsoft.com/en-us/windows/win32/secauthz/null-dacls-and-empty-dacls)

Flag 8 (INHERIT_ONLY) skips the current-object entry. Flag 16 (INHERITED) is
recorded provenance, not a skip or reordering rule. Other low inheritance flags
describe inheritance but do not synthesize a child descriptor here. The
preferred canonical deny ordering is not substituted for actual supplied
order. [Microsoft ACE flags](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-ace_header),
[Microsoft preferred ACE order](https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl)

## Explicit incompleteness

Every ACE is inspected before any supported conclusion, even after an early
sufficient allow or on an inherit-only entry. Other ACE types, object-specific
and callback or conditional semantics, high mask bits, high flags, zero or
non-low16 desired access, and creator/owner/principal-self substitution SIDs
produce `incomplete` with an empty evaluation trace. This conservative whole
projection policy does not claim every unsupported ACE would affect actual
Windows access. Type-tag observations do not validate omitted object GUIDs or
callback bodies. Unknown model fields fail intake instead of being discarded.

No owner-rights resolution, restricted-token second pass, privileges, SACL,
mandatory integrity, AppContainer, central access policy, object GUID tree,
inheritance construction, authenticated group expansion or Windows version
behavior is evaluated. The analyzer is not a replacement for Win32 AccessCheck.
[Microsoft AccessCheck inputs](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)

## Integrity, costs and outputs

The owned `WindowsDaclAnalysis` supports `to_dict`, `to_json`, `from_dict` and
`from_json`. Its captured source model remains part of the unsigned report.
Intake re-derives the complete trace, outcome, software bounds, source digest,
flags and domain-separated content address. Source inspection authenticates
nothing: a self-consistent alternative model can produce a different report.
`verify_supplied_windows_dacl_analysis(report, model=original)` separately
compares the complete re-derived original-source document and rejects such a
replacement. Neither operation verifies provenance, currentness or live use.

Fixed software ceilings are 1 MiB per model or report, 8192 visited nodes,
depth 12, 512 printable ASCII bytes per string, 256 ACEs, 128 unique token SIDs,
and 256 trace entries. Collection structure, escaped quote/backslash bytes and
repeated subtrees are charged before serialization, copying or hashing. These
ceilings compose: an otherwise count-bounded document can still exceed its
aggregate cost limit. Native subclasses, boolean or float integer aliases,
cycles, oversized integers, unknown fields and duplicate JSON members fail.
Raw JSON byte, node, depth, scalar and escape costs are checked before decoding.
Integer spelling permits a single optional minus and the ordinary JSON zero or
non-leading-zero decimal grammar, bounded to magnitude 2^63 - 1 before decoding.
Malformed repeated signs and leading zeros return `WindowsDaclAnalysisError`
before integer conversion. Valid JSON negative zero remains a decoded zero;
declared model and report fields still enforce their exact native semantics.

The result distinguishes `supplied_dacl_allows_requested_bits`,
`supplied_dacl_denies_requested_bits` and `incomplete`, never a vulnerability or
an actual grant. `effective_access_proven`, `descriptor_authenticated`,
`token_authenticated`, `live_use_approved` and `qualification_claimed` always
remain false. Authority, target, execution, routing, qualification, deployment,
network, provider, credential and process effects remain `none`. No signer,
trusted clock, transport, credential resolver or runtime port exists.

Supplied SID and descriptor projections are retained in the report. Inputs
must be inert or appropriately sanitized by the caller; content addressing is
not a privacy, secret-sanitization or source-authentication guarantee.

The synthetic tests cover genuine ordered bit arithmetic, independent small
mask enumeration, null/empty/absent cases, enabled and deny-only user SIDs,
inheritance flags, unsupported branches, exact count and cost limits, detached
sources, native aliases, cohashed false reports and original-source replay.
