# Supplied CD, release provenance and GitOps lineage projection

This R0 partial component serves existing specialist `AOE-GC-D17-S03`,
capability `army.gc.d17.s03`, vector `AV-GC-D17-S03-01`, package
`IWP2-AOE-GC-D17-S03`, and wave `IW2-015`. It adds partial A7.4 offline
evidence only. It does not complete the specialist, candidate, qualification,
independent-validation, or live-use gate.

`analyze_cd_release_provenance(*, source_content: bytes, source_id: str)`
accepts one bounded UTF-8 JSON source with exactly `schema_version` (`v1`),
`facts_complete`, `lineage_complete`, `source_revisions`, `builds`, `releases`,
and `gitops_declarations`. A source revision declares an ID and SHA-256 commit
address. A build declares the source revision ID, input and artifact digests,
and a supplied provenance disposition (`verified`, `failed`, or `unknown`). A
release declares its build, artifact digest, and approval disposition
(`approved`, `denied`, or `unknown`). A GitOps declaration declares the
desired artifact address and a supplied observed state (`present`, `absent`,
or `unknown`); only `present` carries an observed artifact digest. No source
code, build recipe, secret, repository URL, artifact bytes, provider response,
or deployment instruction is accepted. Duplicate JSON keys, unknown fields,
duplicate IDs, noncanonical digests and over-bound data fail closed.

When supplied premises are complete, the projection compares the exact
source/build input, build/release artifact, and release/desired artifact
digests. Missing linked records or incomplete premises remain `unknown`.
Known mismatches are `candidate_declared_lineage_conflict`. A release labeled
approved while its build provenance is labeled failed is
`candidate_release_gate_conflict`. Unknown provenance or approval remains
`unknown`; failed provenance or denied approval otherwise means
`declared_blocked`. A supplied absent observation is
`declared_not_observed`, not evidence of a failed deployment. A present
observed digest different from desired is
`candidate_observed_artifact_mismatch`; exact supplied agreement is
`declared_consistent`. These are comparisons of unverified declarations,
not an attestation, release authorization, compromise, or live deployment
finding.

The report includes exact original source digest and byte count,
per-declaration projections, summary counts, limitations, and no-effect
flags. `CdReleaseProvenanceReport.from_json` validates only local structure
and address. It does not establish derivation or source provenance. For
trust, `verify_cd_release_provenance(report, *, source_content, source_id)`
replays exact original source bytes and compares the entire report.

`analyze_supplied_cd_release_provenance(model)` is the catalog adapter. Its
exact native model contains `source_id` and `source`, where `source` matches
`component_fixture()`. The synthetic common-envelope example is
`examples/offline-cd-release-provenance-component.json`. Its R0 dry run has
empty network, filesystem, process, and credential resources. It performs
no Git, CI, registry, GitOps, cluster, credential, process or network action
and grants no target, authority, routing, execution, qualification or
deployment effect.
