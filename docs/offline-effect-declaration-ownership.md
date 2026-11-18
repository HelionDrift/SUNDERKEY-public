# Offline effect declaration ownership

Effect labels are metadata, not authority. Content-addressed records must retain
the exact declarations accepted at construction. A caller must not be able to
change a record's serialized content by mutating a dictionary retained elsewhere,
or alter later results by mutating an earlier export.

## Constructor-owned declarations

These records copy their supplied declaration once, retain the existing
validation, and store an immutable mapping:

| Module | Records |
| --- | --- |
| Software supply-chain assessment | `AssessmentPlan` |
| Attack-surface discovery | `DiscoveryPlan`, `ObservationBatch`, `DiscoveryReport` |
| Surface drift | `SurfaceSnapshot`, `DriftAssessment`, `RevalidationPlanSet` |
| Assessment guidance | `AssessmentGuidanceCard` |
| Impact policy | `ImpactDemonstrationPlan`, `ImpactDemonstrationReceipt` |
| Scripted transport metadata | `HttpResponseSpec`, `BrowserResultSpec`, `SessionResultSpec` |

Construction and parsing detach supplied dictionaries. Changes to those input
dictionaries do not alter stored IDs, digests, payloads, or nested bindings.
Direct mutation of an owned declaration raises `TypeError`. Use the existing
`to_dict()` and parser interfaces for serialization and round trips. A native
immutable mapping is not a JSON object for direct `json.dumps`, generic
`dataclasses.asdict`, or pickle-based deepcopy. Records without serialization
interfaces remain metadata specifications rather than portable receipts.

Transport specifications preserve the supplied declaration, including non-none
values. They do not replace it with `NO_EFFECTS`. The existing pure no-effects
check and adapter boundaries must still reject an effect-bearing script. Changing
the original input dictionary later cannot turn that rejected declaration into an
accepted one. No transport is invoked by the ownership regression tests.

## Detached exports

Advisory applicability and transitions, API role-response matrices, human-review
routing, metadata impact review, asset reconciliation, and all seven durable
scheduler contract types return fresh effect dictionaries. A schedule's nested
retry declaration is also detached from its parent and the module constant.
Updating, removing, or adding exported labels does not change another export, a
new record, or a content-addressed record. Tampered portable records still fail
their existing parser or replay checks.

Valid serialized content, IDs, and digest domains are unchanged. This is local
ownership integrity, not authentication of the source, evidence of an effect,
live currentness, target authorization, scheduling, execution, deployment,
qualification, or a deployed adapter guarantee.

```powershell
$env:PYTHONPATH = 'src'
python -m unittest tests.agents.test_offline_effect_declaration_ownership -q
```
