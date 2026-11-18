# Offline Report Finding Origins

`verify_report_finding_origins` checks a supplied `PentestReport` against exact,
locally supplied `FindingSnapshot` originals. Each reported finding needs a
complete snapshot chain from version one through the reported head. The
verifier reparses every original, checks the append-only parent chain, and
matches the head to the report's finding lifecycle reference.

The matching fields are finding ID, snapshot digest, lifecycle state,
`updated_at`, vulnerability class, severity, CWE, an optional CVSS vector,
and reported evidence digests. Extra, missing, reordered, altered, or
substituted snapshots fail closed. A report's asset ID and operation ID are
not compared to `FindingIdentity.asset` and `affected_boundary`: the latter
are normalized semantic descriptions, not guaranteed resource identifiers.
The result explicitly marks that identity binding as `not_proven`.

The local verifier accepts at most 200 reported findings, 4,096 supplied
snapshots, and 2,048 embedded event copies across those snapshots. The event
bound limits the repeated parsing cost of complete histories. A larger
history needs a separate bounded review workflow, not a raised limit without
resource analysis.

The result is `matched_local_originals`, not an approval. It does not prove
that the supplied head remains current in a store, that a reviewer or
authority was authenticated, or that a local history cannot be rolled back.
No source port, database, target, or network operation is invoked. Every
authorization, qualification, and target effect is `none`. A production
publication or positive action still needs independently verified current
sources and fresh authority.
