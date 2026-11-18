# Source-replayed offline remediation case review

`build_remediation_case_review` joins the original remediation context, exact
plan, deadline and delivery view, and any supplied retest plan, observation,
closure recommendation, and risk exception. This is an advisory review packet,
not a finding publication, approved change, live retest, exception renewal,
authenticated ticket update, or qualified fix.

## Complete lineage and missing stages

The reviewer reconstructs every typed contract and checks the original
context-to-plan join. A supplied retest must replay from the complete plan,
including every item and its restoration requirements. A supplied observation
must bind that exact retest, cover every required gate once, and fall within
the retest's declared observation window. Nonpassing and inconclusive results
remain valid review inputs. Missing evidence is explicitly reported rather
than silently interpreted as a pass.

The four review stages distinguish a plan without a retest, a retest awaiting
an observation, an observation awaiting a closure recommendation, and a
source-replayed historical recommendation. Later-stage records cannot be
supplied without their exact predecessors. Source records after the explicit
`as_of` time are rejected. A historical recommendation is verified using its
original review time and complete inputs, not by reissuing it at `as_of`.

The gate summary retains each asserted disposition and indicates whether the
required evidence and rollback/cleanup digests are present. Digest presence
is not authenticated evidence custody or proof that a retest executed. Proposed
inherent, residual, and reduction points are copied from the plan, not measured
or independently validated risk reduction.

## Historical recommendations and exceptions

`historical_closure_disposition` records the source recommendation only. The
case always remains `review_required`; every workflow item remains
`unverified`. A closed ticket or a historical `closed_nonqualified`
recommendation does not remove an overdue service target or authorize a
current finding transition.

Declared context, plan, and retest windows are compared with `as_of`. The exact
expiry instant is no longer considered open in this current view. This does
not change the existing historical closure contract's inclusive review boundary.
Even an open declared window leaves `live_source_freshness="not_established"`.
No current authority, revocation, provider state, or external source is fetched.

An asserted exception must reference the exact context and plan and only
items and controls within that plan. Approval must fall within the original
plan's declared lifetime. The shared exception source verifier rejects approval
before plan creation or after plan expiry, even for an unused exception.
Its current declared exception and control windows and asserted item coverage
are separately displayed. Expired
exceptions and controls remain visible without renewal. A recommendation
made while an exception was valid may replay historically after expiry, but
it cannot establish current risk acceptance. `used_by_historical_closure`
distinguishes a supplied exception from one actually bound by the historical
recommendation. Unused partial control coverage is flagged; a recommendation
that relied on it still fails the full closure replay.

## Replay, schema, and effects

`verify_remediation_case_review` regenerates the entire packet from the same
explicit source set, review time, and delivery age limit. It rejects omitted
or substituted sources, changed nested results, extra fields, and
Boolean-to-integer substitutions. Source order does not affect the digest.
The workflow's limits of 2,048 targets and 4,096 delivery observations apply.

The closed output schema is
`registry/schemas/remediation-case-review-v1.schema.json`. Its nested workflow
schema is the local URN `urn:sunderkey:remediation-workflow-review:v1`; validation
must register that bundled schema locally rather than resolve it over a network.
Schema validation checks shape, false claims, and no-effect declarations.
Content addresses, calendar times, source joins, and historical recommendation
replay remain runtime checks.

Identity, provenance, retest execution, risk acceptance, and remediation
claims are all false. All authorization, closure, execution, integration,
network, notification, persistence, qualification, ticketing, and finding
publication effects are `none`. The packet adds an offline portion of V9.16
without qualifying production readiness. Authenticated ITSM provenance,
secure assignment custody, renewal authority, live evidence and revalidation,
qualified closure, and production operations remain separate requirements.

## Bounded local CLI

The read-only commands accept one complete UTF-8 source archive and print only
advisory JSON. They do not create an output file themselves. Shell redirection
is optional and is controlled by the operator; use distinct paths so an input
is not overwritten before the command reads it.
The case archive uses compact canonical JSON and reserves the terminating
newline within the saved-review byte cap. It is fully serialized and size
checked before any output is printed. Standard CLI output uses the binary
stdout buffer for that ASCII packet, preserving its single LF newline on
Windows as well as POSIX. Text-only capture streams remain supported for
embedded use; a caller-provided stream or shell may re-encode or transform
output, so its saved file must still satisfy the loader's independent byte cap.
The CLI's write-collision precheck does
not resolve protected input paths when there are no output paths to compare;
the source loader retains responsibility for rejecting links and network paths.

```bash
export PYTHONPATH="src"
python -m sunderkey.cli remediation-case-review \
  --input remediation-sources.json > remediation-review.json
python -m sunderkey.cli remediation-case-review-verify \
  --input remediation-sources.json --review remediation-review.json
```

The source object has exactly these fields:

- `schema_version`: integer `1`;
- `context` and `plan`: complete exact contract `to_dict()` forms;
- `as_of`: UTC review time, ending in `Z`;
- `targets` and `delivery_observations`: lists of complete workflow record
  `to_dict()` forms, including their content digests;
- `retest`, `retest_observation`, `closure`, and `exception`: exact respective
  contract forms or explicit `null` when not supplied; and
- `max_delivery_observation_age_seconds`: integer from 1 to 604,800.

Explicit nulls preserve absent stages. Later-stage records still require their
predecessors. Empty content addresses, omitted fields, substituted sources,
unknown fields, and Boolean or float substitutions for integers are rejected.
Duplicate object keys, invalid UTF-8, nonfinite numbers, non-JSON values, and
malformed JSON are rejected without printing a partial result.

Source files are limited to 8,000,000 bytes and saved review files to 4,000,000
bytes. Parsed and programmatic inputs also have those canonical byte limits,
a maximum depth of 24, 200,000 JSON value nodes, 64 keys per object, and 4,096
entries per list. The target list remains separately capped at 2,048. All
limits apply before a result is printed; whitespace does not evade file limits.

Only regular local files are accepted. Network-style paths, symlinks, reparse
points, and linked parent directories are refused before descendant inspection.
Reads compare file identity, size, modification time, and a platform-appropriate
timestamp before opening, on the descriptor, and after reading. The timestamp
is POSIX change time or Windows birth time when available; older Windows Python
falls back to its creation-time `ctime` field. Windows `ctime` is not assumed
to be an interchangeable stable path/descriptor identity timestamp. Detectable
replacement or mutation fails closed. These
checks are not source authentication or a trusted immutable storage service.

`registry/schemas/remediation-case-request-v1.schema.json` describes the closed
archive shape. Its remediation contract references point to the bundled
`remediation-validation-contract-v1.schema.json`; register that existing schema
locally and do not fetch its HTTPS identifier. Schema validation alone cannot
replay source lineage or establish evidence provenance.

Verification reports `verification_kind="offline_source_replay"`, keeps the
case `review_required`, and leaves live source freshness `not_established`.
It cannot approve the historical result for current execution or publication.
