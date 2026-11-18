# Offline Collaboration Review Custody

`offline_collaboration_review_custody.py` records local, unsigned operator
assertions about a cross-domain collaboration handoff. It does not authenticate
reviewers, producers, sources, tenants, scopes, or clocks. A favorable pair of
assertions never becomes an accepted independent review, verified world edge,
finding, target authorization, assignment, or publication decision.

## Source and Scope Boundary

Each append first replays the collaboration review handoff from its separate
original task and relation inputs and the current specialist catalog. The
store then binds the graph, handoff, and catalog digests to its first entry.
It refuses later writes against another handoff. Review records identify one
current claim or hypothesis and preserve its exact item digest and status.
They retain only generated identifiers, digests, reviewer assertions, and
closed reason codes, not original source bodies or free-form rationales.

The store constructor receives a tenant identifier and declared scope ID.
Those are caller assertions. The graph's scope basis is
`caller_declared_unverified`; matching labels are not evidence that separate
sources share a real target, tenant, identity, or authority. Source replay
occurs before the local SQLite write, without a cross-store transaction.
`verify_current` must replay the original sources again for any later review
use, but even that does not establish atomic currentness or authentic origin.

## Local History

The reference store is one bounded SQLite database with a dedicated
application ID and schema version. Creation is exclusive. An existing file is
verified read-only and never adopted merely because it is empty. Symlink and
Windows reparse paths are refused, including parent-directory aliases. The
local database, entry, and history-length limits fail closed before replay.
These path checks do not replace operating-system directory-handle controls
against an adversary concurrently changing filesystem entries.

Each request has a content-bound
idempotency key. Entries form a monotonic hash chain. The current head and
entry are updated in one transaction. Review rows are immutable. The store
rejects request-ID rebinding, a second active assertion in the same role for
one item, and one asserted subject filling both Control and Assurance roles
on the same item. A same-subject revocation preserves the earlier record and
allows a later replacement. Revocation uses verified historical local custody
without requiring old source files to remain current. It is an unsigned
withdrawal, not an authenticated authority decision. A contradictory or unassessed source item cannot
receive an `accept_for_review_only` assertion.

`verify_history` checks local schema identity, entry order, content addresses,
the hash chain, idempotency, and active assertion state. It is historical
integrity only. `verify_current` additionally replays the handoff from the
separate current originals and rejects drift in each reviewed item. Its
`dual_operator_assertions_unverified` state means exactly two structurally
separate unsigned assertions, not authenticated review acceptance. A
challenge or missing evidence remains visible as contested or incomplete.

The SQLite file is not externally anchored. Anyone able to replace the
entire database may construct a new self-consistent history. Production
anti-rollback custody, authenticated reviewer and producer identities,
trusted time, independently authenticated source evidence, and real tenant
and scope equivalence require external trust roots and operational controls.

## Effect Boundary

Every history and current summary fixes identity assurance to
`operator_asserted_unsigned`, review status to
`assertions_recorded_not_accepted`, and all operational effects to `none`.
`independent_review_accepted` and `positive_use_approved` remain false.
This module provides no action, network, target, credential, scheduling,
finding, world-edge promotion, qualification, or publication capability.

Focused tests:

```text
python -m unittest tests.agents.test_offline_collaboration_review_custody -v
```
