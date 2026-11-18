# Supplied Linux POSIX mode and access ACL arithmetic

This partial offline algorithm evaluates declared discretionary-access bits. It
does not read a filesystem, resolve an account, invoke a kernel, inspect a
credential, acquire an ACL, or establish effective host access. No result changes
authority, target state, routing, deployment or qualification.

The component is `linux_supplied_posix_acl_arithmetic`, under existing profile
`AOE-GC-D12-S01`, capability `host.linux.local-privilege-escalation`, vector
`AV-GC-D12-S01-01`, package `IWP2-AOE-GC-D12-S01`, and wave `IW2-001`. Its commander
is `AOE-GC-D12-CMD`, group commander is `AOE-HQ-05`, and validator is `AOE-HQ-19`.
The existing blueprint digest is
`sha256:0eeeef8de9328721551f481082889213dbcca8240ad9ebd9ca679ba006415d8c`.
This is not a full specialist, local privilege-escalation procedure, qualified
candidate, host acceptance result or deployment decision.

## Supported semantics

The implementation is independently written mathematical arithmetic. Its
permission-class and mask behavior is pinned to the
[Linux v6.17 POSIX ACL implementation](https://raw.githubusercontent.com/torvalds/linux/v6.17/fs/posix_acl.c)
and the [acl(5) manual](https://man7.org/linux/man-pages/man5/acl.5.html).

Owner, named user, matching group class and other are considered in that order.
An earlier matching class cannot fall back to another class when it lacks the
requested bits. The ACL mask limits named-user and group entries, not owner or
other. A multi-bit request needs all bits from one matching group entry after
the mask. Read from one group and write from another do not jointly satisfy a
read-plus-write request.

The input representation adds canonical named-qualifier ordering to its closed
logical subset. It is not an xattr decoder or a claim to implement every input
accepted by a kernel ACL validator. Unique increasing named UIDs and GIDs prevent
ambiguous repeated entries. Declared mode bits must agree with owner and other
ACL entries and with the mask, or owning-group entry when no mask exists.

## Public interfaces

`src/sunderkey/offline_posix_acl_analysis.py` exposes:

- `analyze_supplied_posix_acl(model)`.
- `analyze_supplied_posix_acl_bytes(*, model_bytes)`.
- `verify_supplied_posix_acl_analysis(report, *, model)`.
- `PosixAclAnalysis.from_dict`, `.from_json`, `.to_dict`, and `.to_json`.

The wrapper owns bounded canonical JSON. It replays the embedded model on every
public read. The separate verifier also compares against the independently
supplied original model. A coherent report for a different valid model remains
inspectable unsigned metadata, but does not verify against the original source.

The closed model contains exactly:

```json
{
  "schema_version": 1,
  "object": {
    "object_ref": "file:synthetic",
    "owner_uid": 1000,
    "owner_gid": 2000,
    "rwx_mode": 487,
    "access_acl": [
      {"tag": "user_obj", "qualifier": null, "permission_mask": 7},
      {"tag": "user", "qualifier": 1001, "permission_mask": 4},
      {"tag": "group_obj", "qualifier": null, "permission_mask": 5},
      {"tag": "mask", "qualifier": null, "permission_mask": 4},
      {"tag": "other", "qualifier": null, "permission_mask": 7}
    ]
  },
  "principal": {
    "principal_ref": "subject:synthetic",
    "fsuid": 1001,
    "fsgid": 2000,
    "supplementary_gids": []
  },
  "requests": [
    {"request_id": "read", "requested_mask": 4},
    {"request_id": "write", "requested_mask": 2}
  ]
}
```

`rwx_mode` is the nine access bits only, as a native integer from 0 through 511.
It is not a full `stat.st_mode`, file type or special-bit declaration. The example
is mode `0747`. Each requested mask is a native integer from 1 through 7: read is
4, write is 2, and execute or directory-search projection is 1. References are
opaque local identifiers, not paths to be opened.

`access_acl: null` selects ordinary owner/group/other mode arithmetic. A supplied
ACL must be nonempty. Tag order is `user_obj`, named `user` entries, `group_obj`,
named `group` entries, optional `mask`, then `other`. Exactly one owner, owning
group and other entry is required. Named entries require one mask. Unqualified
entries use a null qualifier; named entries use an exact bounded UID or GID.
Permission masks are integers from 0 through 7. Default ACLs and unknown fields
are rejected, not ignored or normalized into a clean decision.

The primary GID and supplied supplementary GIDs provide membership. They do not
prove real account membership. Owner and named-user precedence uses the supplied
FSUID. The example returns `allowed_by_supplied_posix_dac` for read and
`not_allowed_by_supplied_posix_dac` for write even though other has all bits.

## Addresses, witnesses and input ownership

The model digest uses `sunderkey.offline-posix-acl-model.v1`; individual requests
use `sunderkey.offline-posix-acl-request.v1`. The report digest uses
`sunderkey.offline-posix-acl-analysis.v1`, with `LPA-` followed by the first 32
uppercase digest hexadecimal characters as its ID. Addresses are over sorted-key
ASCII canonical JSON with a domain and newline prefix.

The report embeds the original parsed model, a class-selection projection,
bounded source-index candidates, sorted request results and exact work counters.
A positive ACL witness refers to one original entry. No combined-group mask is
invented. Mode-only results have no ACL entry witness. Canonical parsed snapshot
provenance is distinct from raw input bytes: JSON whitespace or equivalent ASCII
escapes can encode the same parsed model and produce the same model digest.
Array order remains source-bound even when reversing requests or supplementary
GIDs leaves the arithmetic unchanged. ACL tag or qualifier order is not repaired.

Only exact native dictionaries, lists, strings, integers, booleans and null can
enter the bounded JSON capture. Typed model fields reject booleans, floats,
subclasses and coercions where an integer is required. Outputs are detached;
mutation of caller containers cannot update the wrapper. An incomplete or
coherently rehashed false wrapper must replay before it can be used. This is not
an arbitrary Python-code sandbox or proof of memory isolation.

## Finite costs

Input is limited to 64 KiB, 8,192 native nodes and depth 12. Report intake and
output are limited to 1 MiB, 32,768 nodes and depth 16. Text is bounded to 256
printable ASCII characters. UID and GID declarations range from 0 through
4,294,967,294; this finite unsigned-32-bit subset excludes the invalid sentinel.
It does not establish user-namespace or mount ID mappings.

There are at most 128 supplementary groups, 256 ACL entries, 64 requests,
32,768 matching steps and 8,192 entry-reference witnesses. Duplicate group or
request identities are rejected. Native graph bounds charge repeated shared
subtrees again and refuse cycles. Byte charging includes JSON escapes and the
final primitive. Raw JSON token, string, node and depth checks precede decoding;
integer magnitude is checked before decimal conversion. Duplicate keys at any
level, floats, nonfinite numbers and malformed numeric tokens are refused.

The complete output projection, including fixed-width address overhead, must
fit its budgets before any source, request or report hash is calculated. The
algorithm never materializes a UID space, permission universe or filesystem
tree. Limits describe this software subset, not a host capacity or latency gate.

## Boundaries and validation

Owner UID zero is accepted as a declaration and evaluated only as a DAC class.
The component does not infer root behavior, capabilities or other privilege
overrides. Idmapped mounts, user namespaces, MAC, parent-directory traversal,
sticky bits, setuid/setgid, creation/default ACLs, NFSv4 and remote filesystem
behavior remain unmodeled. An arithmetic rejection is not a live host denial.
No timestamps or live-currentness proof are introduced.

The synthetic test helper is
`tests.agents.test_offline_posix_acl_analysis.component_fixture`. Tests cover
mode classes, masks, no fallback, exhaustive multi-group counterexamples,
canonical ACL structure, integer boundaries, malformed and duplicate JSON,
pre-decoder and pre-hash costs, detachment and cohashed false report replay.
They do not execute a Linux ACL or qualify the specialist. Fixed report flags
keep source authentication, filesystem observation, effective access, live use
and qualification false. All effects remain `none`.
