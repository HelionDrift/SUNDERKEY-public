# Offline specialist request and receipt replay integrity

This repair closes a bounded native JSON replay mismatch in the existing web,
API and authentication specialist adapter contract for roadmap packages A2.5
through A2.11 and repository work item WQ-011. It does not implement a new
specialist, tool, adapter, target action or live service.

## Exact addressed input

Both `SpecialistActionRequest.from_dict` and
`SpecialistActionReceipt.from_dict` reconstruct the existing record and compare
its full canonical JSON document with the supplied document. The shared public
`parse_specialist_contract` entrypoint delegates to those checks. Schema metadata
must contain the native integer `1`, not `true` or `1.0`.

The request's operation policy is also compared using the existing canonical
JSON function. Integer or float aliases cannot stand in for the fixed boolean
`authenticated_session_required`. Boolean or float aliases cannot stand in for
the fixed integer `minimum_principals`. The function already rejects float
values; its existing JSON rules and depth bound remain unchanged.

Previously, Python equality allowed these aliases to be removed during parsing
while preserving a content address for the different, reconstructed document.
The same normalization could accept reordered session, evidence or adapter
operation lists under the original identity. A parsed addressed document now
has to replay exactly. Malformed supplied records are rejected, not repaired,
normalized to another record, or assigned a new content address.

Constructors can still generate their canonical sorted records from valid typed
inputs. Their signatures, identity domains, operation policies, approval and
session requirements, budgets, effects and execution semantics are unchanged.
All 14 operation fixtures retain their pinned request and receipt digests.

## Execution and history boundaries

The regression workflow parses the supplied request before passing it to
`execute_specialist_action`. Rejected aliases therefore invoke no injected
adapter. The existing execution boundary still requires the exact context,
current request, approval and sessions, a supported operation, process-local
replay reservation, exact response correlation and bounded observations.
This repair does not add a new dispatch API or automatic retry.

Receipt parsing remains historical integrity inspection. A valid old receipt
does not need fresh activation merely to be inspected, and parsing it does not
execute an adapter, renew an approval or grant current authority. The existing
historical bytes and identities remain valid.

The fixed effect declarations remain detached from exported dictionaries.
Authority grants and qualification remain `none`; tool implementations and a
network client remain absent. Remote execution remains an explicitly injected
adapter boundary, not built-in target execution.

## Regression evidence and limits

`tests/agents/test_specialist_web_api_replay_integrity.py` uses existing Phase166
native fixtures and deterministic fake adapters. It covers both public parser
entrypoints, changed native JSON types under the old claimed identity, policy
aliases for every operation, list-order replay, unchanged golden identities,
historical receipt inspection and fixed effect statuses. Compatibility checks
also retain the existing cloud/identity and mobile/OT adapter tests.

These are local software checks only. They do not authenticate a supplied
approval, session, tool, evidence producer or adapter declaration. They do not
provide trusted containment, durable replay storage, credentials, provider
transports, independent validation, qualification or production acceptance.
The parser is not a sandbox for arbitrary Python code and does not claim
protection against concurrent or callback mutation of existing objects. No
external effect can be undone by this repair.
