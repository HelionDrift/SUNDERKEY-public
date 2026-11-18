# Supplied SemVer precedence and explicit intervals

This partial offline algorithm evaluates caller-supplied version labels under
[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). It compares their
precedence and tests membership in explicitly declared intervals. It neither
resolves packages nor interprets npm range expressions or vulnerability advisories.

The existing owner is AOE-GC-D17-S04, capability army.gc.d17.s04, vector
AV-GC-D17-S04-01, work package IWP2-AOE-GC-D17-S04 and wave IW2-016. The commander
is AOE-GC-D17-CMD, group owner AOE-HQ-05 and validator AOE-HQ-19. The source
blueprint is
`sha256:db4571f5aec671c800119f2dbb1b2b25442d818e3f3a76ae95fc3fa0f4203849`.
The component is `javascript_supplied_semver_interval_arithmetic`; initial
roadmap evidence is A7.4 only. It is not a completed or qualified specialist.

## Public interface and closed model

`analyze_supplied_semver_intervals(model)` accepts exact native integer-only JSON
families. `analyze_supplied_semver_intervals_bytes(*, model_bytes)` accepts local
native ASCII JSON bytes. Neither function performs file, process, network,
credential, package registry or external callback operations.

The model has exactly these fields:

```json
{
  "schema_version": 1,
  "versions": [{"version_id": "release", "version": "1.0.0+linux"}],
  "comparisons": [],
  "intervals": [{
    "interval_id": "stable",
    "lower": {"version": "1.0.0+left", "inclusive": true},
    "upper": {"version": "1.0.0+right", "inclusive": true}
  }],
  "membership_queries": [{
    "query_id": "declared-membership",
    "version_id": "release",
    "interval_id": "stable"
  }]
}
```

A comparison is exactly `comparison_id`, `left_version_id` and
`right_version_id`. IDs are unique within each typed table, case sensitive,
1 through 64 characters, and use ASCII alphanumerics plus underscore, period
and hyphen, starting with an alphanumeric character. Repeated version labels
under distinct IDs are allowed. Dangling references and duplicate typed IDs
are rejected. Table order remains part of source identity.

Each interval bound is null or exactly a version string and native `inclusive`
boolean. Null means unbounded. Lower precedence greater than upper precedence
is a software input rejection. Equal endpoints with either endpoint open are
a supported empty interval. Both closed endpoints include their entire
precedence-equivalence class, including distinct build metadata. There is no
npm-style prerelease exclusion: an unbounded interval includes prereleases.

## Supported arithmetic

The independently written manual grammar requires three decimal core numbers
with no leading zeroes except zero itself. Prerelease and build identifiers are
nonempty ASCII alphanumeric or hyphen sequences separated by periods. Numeric
prerelease identifiers have no leading zeroes. Build identifiers may have them.
Whitespace, a `v` prefix, shorthand, wildcard, range operator and Unicode labels
are rejected rather than normalized.

Core and numeric prerelease values remain bounded decimal strings. Numeric
comparison uses digit count then lexical order, not machine integer conversion.
Numeric prerelease identifiers precede nonnumeric identifiers; nonnumeric
identifiers use case-sensitive ASCII lexical order. A shorter equal prefix of
prerelease identifiers has lower precedence. A release has higher precedence
than a prerelease with the same core. Build metadata is retained exactly but
ignored only when computing precedence, as required by specification rule 10.

Comparison rows use only `less`, `equal` or `greater`. Membership rows use only
`inside` or `outside`, with lower and upper checks and an explicit empty flag.
They are not statements that a package is affected, vulnerable, safe, available,
compatible or authorized. Version labels and interval declarations are unsigned
caller input, not immutable package contents or authenticated advisory evidence.

## Bounds and rejection ordering

The specification itself does not impose these limits. This software subset
uses explicit ceilings:

| Quantity | Ceiling |
| --- | ---: |
| Raw or canonical model bytes | 1,048,576 |
| Complete report bytes | 2,097,152 |
| Native or raw model nodes / depth | 32,768 / 16 |
| Native or raw report nodes / depth | 65,536 / 20 |
| Versions / comparisons | 256 / 256 |
| Intervals / membership queries | 128 / 512 |
| Version label bytes | 512 |
| Combined prerelease and build identifier count | 64 |
| Record ID bytes | 64 |
| Cumulative work per public operation | 4,194,304 charged units |

Source capture owns every occurrence, including shared subtrees, while rejecting
cycles, subclasses, floats, nonnative aliases and signed64 JSON integer overflow.
The root schema integer is not interchangeable with `true` or `1.0`. Bounds
require actual booleans. Strings, escapes, depth, nodes and raw integer lexemes
are checked before JSON decoding; duplicate keys at every level are rejected.
Native budgets precede canonical dumps and address hashes. All derived rows and
the complete report, including fixed-width addresses, are cumulatively reserved
before hashing. Raw ASCII copying, parsing, comparisons, captures, canonical
writes, preimages, replay equality scans and separate original-model verification share one operation
budget. Limits are simultaneous ceilings, not a promise that every combination
of individual maxima fits the aggregate operation budget.

A software ceiling raises `SemverIntervalAnalysisError`. It never produces a
fabricated invalid version result, vulnerability finding or successful analysis.

## Exact replay and provenance limits

The frozen `SemverIntervalAnalysis` owns canonical report text.
`from_dict`, `from_json`, `to_dict` and `to_json` reconstruct the full embedded
source-derived arithmetic. They reject false results even when the outer hash
has been truthfully recomputed. Exports are detached, and at-use reconstruction
rejects an altered or incomplete wrapper. This is integrity against the supplied
model, not an arbitrary Python execution sandbox or concurrent memory guarantee.

`verify_supplied_semver_interval_analysis(report, *, model)` independently replays
the separately supplied original model. A self-consistent report for a different
source, including a build-only change, cannot substitute for that original.
Hashes use separate model and report domains, unchanged literal case and table
order, and exact canonical ASCII JSON. Whitespace and equivalent JSON escapes
do not have raw-byte provenance: byte intake binds the canonical parsed snapshot,
not the original JSON spelling. Version string spelling and build metadata do
remain bound.

All authority, target, execution, network, provider, credential, process, routing,
qualification, deployment and publication effects are `none`. Source
authentication, advisory truth, vulnerability verification, package availability,
compatibility, live approval and qualification flags are false. No deployment,
routing, current authority, reviewer acceptance or vendor parity follows.

## Synthetic checks

The owned test module uses an independent small-number tuple oracle for 1,296
pair comparisons and 504 interval memberships, the specification's prerelease
ordering chain, bounded large decimal values, and explicit build equivalence.
It also checks source references, exact native distinctions, duplicate JSON,
pre-decoder and pre-hash ceilings, cumulative export and verification work,
genuine source-bounded/report-node exhaustion, detachment, coherently readdressed
false results and separate-original replay.
`component_fixture()` returns a fresh closed model with known prerelease,
release and build-equivalence outcomes; it is synthetic arithmetic only.
