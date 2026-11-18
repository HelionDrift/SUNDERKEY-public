# Specialist qualification scenario corpus

## Purpose

The specialist scenario corpus converts the reviewed Army v2 planning artifacts into a deterministic qualification scenario matrix. It creates six non-operational scenario records for every specialist whose source bindings are complete and consistent.

The current reviewed artifacts support 391 specialists and 2,346 scenarios. Each specialist receives these variants:

1. Positive case with reproducible evidence.
2. Negative case that must not be reported as a finding.
3. Ambiguous authority or target case requiring abstention.
4. Adversarial or misleading evidence case.
5. Cross-specialist handoff and conflict-resolution case.
6. Cleanup, restoration, and residual-effect verification case.

The corpus is a qualification planning artifact. It cannot authorize an action, qualify a specialist, change routing, dispatch work, or execute a tool.

## Reviewed inputs

The builder consumes exactly these registry artifacts:

| Source role | Artifact |
| --- | --- |
| Expert registry | `army-v2.json` |
| Attack vectors | `attack-vectors-v2.json` |
| Capability graph | `capabilities-army-v2.json` |
| Qualification plans | `qualification-plans-army-v2.json` |
| Candidate blueprints | `candidate-blueprints-army-v2.json` |
| Commander work packages | `implementation-work-packages-v2.json` |

Each source binding records the artifact ID, artifact version, exact raw-file SHA-256 digest, canonical JSON SHA-256 digest, and any declared catalog digest. The builder verifies every available declared digest and the cross-catalog digests before generating a scenario.

## Scenario contract

Every scenario is bound to:

- one specialist profile and profile version;
- one attack vector and qualification scenario family;
- primary and supporting capabilities;
- exact prerequisite observations;
- identifier-only proof anchors;
- prohibited actions, stop conditions, and critical failures;
- restoration checks and expected evidence;
- the declared independent validator;
- the domain and group commanders plus the commander work package;
- allowed action tiers and the maximum permitted action tier;
- known source blind spots;
- the exact raw content hashes of all six source artifacts.

Scenario records do not include exploit payloads, target instructions, credentials, endpoints, or request templates. They preserve the source control language without adding product-specific or target-specific detail.

## Determinism and content addressing

Canonical JSON uses sorted keys, compact separators, ASCII escaping, and rejects non-finite numbers. Each scenario digest covers the complete scenario body plus a domain separator. Its scenario ID is derived from the first 128 bits of that digest. The corpus digest covers the complete corpus body plus a separate domain separator, and the corpus ID is derived from that digest.

The builder rejects duplicate JSON keys, duplicate source record identifiers, content-address collisions, stale declared hashes, mismatched cross-catalog hashes, unknown specialist records, and non-none authority or operational effects.

## Truthful gap behavior

The builder does not synthesize missing source detail. A specialist with a missing or inconsistent profile-level binding receives a deterministic gap record and no scenarios. Coverage reports include:

- specialist profiles observed;
- eligible profiles;
- profiles with gaps;
- expected, generated, and missing scenario counts;
- exact counts for each gap reason;
- a completion flag.

The current source set reports zero gaps. If a future valid source set omits one specialist plan, the corpus reports one gap profile and six missing scenarios instead of inventing a plan.

Source-wide integrity failures are not profile gaps. A stale catalog digest or broken cross-catalog binding fails closed because no profile can be trusted against that source set.

## Resource limits

`ScenarioCorpusLimits` applies ceilings before and after construction:

- per-source and total source bytes;
- JSON nodes and nesting depth;
- specialist and scenario counts;
- final canonical corpus bytes.

The defaults accommodate the reviewed Army v2 artifacts while bounding memory use. A caller may lower a limit for a constrained environment, but raising a limit should be a reviewed configuration change.
Each source must be a regular file. The builder caps each read at the configured
byte limit and rejects replacement or modification of the opened file or path
during loading. Nonblocking and no-follow open flags are used where supported.

## Python usage

```python
from pathlib import Path

from sunderkey.specialist_scenario_corpus import (
    build_specialist_scenario_corpus,
)

corpus = build_specialist_scenario_corpus(Path("registry"))
document = corpus.to_dict()

assert document["coverage_summary"]["scenario_count"] == 2346
assert document["qualification_effect"] == "none"
assert document["routing_effect"] == "none"
assert document["authority_effect"] == "none"
assert document["execution_effect"] == "none"
```

Callers may store `corpus.document_json` as the canonical serialization. Persistence, review approval, candidate execution, and qualification admission remain separate workflows.

## Verification

The focused tests verify full current coverage, exact variant cardinality, representative API bindings, source hashes, content addresses, canonical output, explicit gap accounting, resource ceilings, tamper rejection, zero effects, and schema conformance.

```powershell
$env:PYTHONPATH = "src"
python -m unittest tests.agents.test_specialist_scenario_corpus_phase163
python -m ruff check --no-cache src/sunderkey/specialist_scenario_corpus.py tests/agents/test_specialist_scenario_corpus_phase163.py
python -m ruff format --check --no-cache src/sunderkey/specialist_scenario_corpus.py tests/agents/test_specialist_scenario_corpus_phase163.py
```
