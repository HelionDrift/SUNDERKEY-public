# Attack technique reference catalog v3

The v3 catalog extends the single generic coverage anchor for each of the six Phase 157 reference profiles with concrete, infrastructure-independent analysis records. It is a design and evidence contract. It grants no target authority, qualification, routing, execution, or deployment effect.

## Scope

The checked registry contains 18 records, with three records for each reference profile:

- `AOE-GA-D01-S01`: certificate transparency expansion, passive DNS correlation, and public repository metadata hints.
- `AOE-GB-D06-S09`: peer object substitution, nested subresource ownership, and mixed-ownership bulk selectors.
- `AOE-GA-D03-S14`: nested group membership, delegated role activation, and toxic entitlement combinations.
- `AOE-GC-D14-S01`: wildcard IAM policy paths, cross-account role trust, and organization policy boundaries.
- `AOE-GC-D11-S08`: writable service configuration, privileged scheduled tasks, and startup artifacts.
- `AOE-GD-D19-S01`: unauthorized inter-zone flows, conduit protection gaps, and temporary segmentation restoration.

Every record carries profile and v2 vector bindings, a distinct mechanic, prerequisites, observables, safe proof steps, negative controls, cleanup and restoration checks, blind spots, standards mappings, effect fields, and its own content digest. Safe proof is limited to immutable synthetic fixtures and pure offline evaluation. The records contain no exploit payload, real target, live credential, or operational authorization.

## Standards pins

Mappings resolve only through the source table embedded in the catalog. The initial source set is pinned to MITRE ATT&CK Enterprise 19.2 released on 2026-08-05, OWASP API Security Top 10 2023 released on 2023-07-03, and IEC 62443-3-3:2013 released on 2013-08-07. Each mapping repeats the source version and release date. The loader rejects an unknown reference, mismatched relationship type, missing release date, source version drift, and labels such as `rolling`, `latest`, `current`, or `stable`.

ATT&CK mappings state related technique context. The API mappings state an exact API risk relationship to `API1:2023`. IEC mappings state control alignment. These relationship labels prevent contextual references from being presented as exact equivalence.

## Determinism and content addressing

The builder sorts sources and technique records by identifier. Canonical JSON uses sorted object keys, compact separators, ASCII encoding, and rejects non-finite numbers. A technique digest covers the technique after removing `technique_sha256` and adding the domain `sunderkey.attack-technique-catalog.v3.technique`. The catalog digest covers the catalog after removing `catalog_sha256` and adding the domain `sunderkey.attack-technique-catalog.v3`.

The strict loader also rejects:

- unknown, duplicate, non-contiguous, or out-of-order technique IDs;
- fewer than three records for any reference profile;
- duplicate or generic mechanics and duplicate detail sets;
- incorrect profile, family, or v2 vector bindings;
- incomplete, duplicate, unpinned, or unused standards sources;
- mapping references or relationships outside the source allowlist;
- any authority, qualification, routing, execution, or deployment effect other than `none`;
- incorrect coverage counts, record hashes, or catalog hashes.

The JSON Schema provides an independent structural check. The Python loader performs the semantic and content-address checks that JSON Schema cannot express.

## Build and check

From the repository root with the package source on `PYTHONPATH`:

```powershell
$env:PYTHONPATH = "src"
python scripts/build_attack_techniques_v3.py --check
python -m unittest tests.agents.test_attack_techniques_v3_phase157
ruff check src/sunderkey/attack_techniques_v3.py scripts/build_attack_techniques_v3.py tests/agents/test_attack_techniques_v3_phase157.py
```

Run the builder without `--check` only when intentionally regenerating both checked artifacts. It validates the generated document against the Draft 2020-12 schema before writing.

## Files

- `src/sunderkey/attack_techniques_v3.py`: strict data model, semantic validation, hashing, and loader.
- `scripts/build_attack_techniques_v3.py`: deterministic source data, schema builder, and drift check.
- `registry/attack-techniques-reference-v3.json`: checked catalog.
- `registry/schemas/attack-technique-catalog-v3.schema.json`: checked Draft 2020-12 schema.
- `tests/agents/test_attack_techniques_v3_phase157.py`: deterministic and negative-path coverage.
