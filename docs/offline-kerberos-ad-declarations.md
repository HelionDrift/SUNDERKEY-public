# Supplied Kerberos AD Declarations

The `AOE-GC-D11-S02` partial specialist, component
`supplied_kerberos_ad_declarations`, compares caller-supplied service, account,
SPN, delegation-mode, and encryption-label declarations with a caller-supplied
local policy. A repeated SPN reference across distinct account references,
unconstrained delegation outside the supplied policy, constrained delegation
without supplied targets, or an encryption label outside the supplied allowlist
is reported only as a declaration mismatch. These labels are not a Kerberos
implementation assessment or an exploit classification.

The exact native JSON model has `schema_version: 1`, a bounded `source_id`,
`inventory_complete`, `policy`, and one to 64 `services`. Account, service,
and SPN references are opaque SHA-256 references. The closed encryption labels
are `aes128`, `aes256`, `rc4`, and `other`; delegation modes are `none`,
`constrained`, and `unconstrained`. Incomplete inventory yields `unknown`, no
candidates, and one unknown row per service. Replay verification recomputes
the report from the separately supplied original model.

The component does not query a directory, obtain a ticket, authenticate,
handle credentials, contact a network or target, prove effective access,
publish a finding, or grant qualification. The
[synthetic example](../examples/offline-kerberos-ad-declarations-component.json)
uses fictitious digest references only.
