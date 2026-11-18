# Offline API Signed Expectation Dossier Companion

`sunderkey.offline_api_signed_expectation_dossier` builds a separate companion
to the nonfinding API reviewer dossier. It replays the dossier from its
original review, planning, and retest sources. It also verifies a locally
signed expected-access assertion set against the same exact prior and second
API case sources. The join checks both case identities and result digests, the
retest observation-change label, tenant binding, and scope ID. Entry and exit
case replays detect source changes made during the intervening checks.

The companion contains only digests, the observation-change label, and
explicit limitation flags. A saved companion must be verified again against
the original inputs; its public content hash alone is not provenance. Saved
documents must match an exact native, shallow schema with bounded string and
effect values before comparison, so arbitrary supplied trees are not fully
serialized by the companion verifier. The directly supplied dossier, signed
retest binding, expectations, and attestation documents receive separate
native-shape and value bounds before any upstream source replay or document
verification. At most 1,000 proposed task IDs and 64 principal expectations
are accepted in this companion.

The nested JSON-like values in `dossier_options` are also walked before any
replay. The walk accepts only native dictionaries, lists, tuples, JSON scalars,
and exact known typed adapter, case-source, scope, scheduling, registry, and
target context objects. It rejects unexpected mapping subclasses, cycles,
nonfinite numbers, depth above 64, more than 100,000 nodes or container items,
an individual string above 1,000,000 UTF-8 bytes, or more than 8,000,000 UTF-8
string bytes in total. Case-source results, invocation inputs, and evidence
metadata are traversed. Raw signed scope and adapter manifest documents have
a 1 MiB cap; raw target context documents have an 8 MB cap. Registry entry
counts are checked before projecting their public fields into the bounded
walk. These checks limit materialization before upstream replay. They do not
replace upstream typed verification or make independent mutable sources atomic.

This remains a local, nonauthoritative rehearsal. The signature is checked
against a caller-pinned key, not an independently authenticated policy owner.
It does not establish that the policy was committed before observation. The
signature covers a scope ID but not the exact scope digest shown by the
reviewer dossier. Neither a finding nor report publication is established,
and positive use is not approved. The module itself does not call a target,
publish a report, or access a network. The upstream API case verifier requires
the exact native API analyzer and rejects a substituted callback before it
can run. The source checks are not an atomic snapshot across independent
systems.

The original reviewer dossier and API routes remain unchanged. This companion
does not authorize an action or alter the review decision.

Run the focused checks from the repository root:

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_offline_api_signed_expectation_dossier -v
python -m ruff check src/sunderkey/offline_api_signed_expectation_dossier.py tests/agents/test_offline_api_signed_expectation_dossier.py
```
